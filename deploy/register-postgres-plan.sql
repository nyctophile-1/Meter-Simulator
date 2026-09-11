-- Read matching rows once; indexed temporary snapshots avoid 100,000 repeated table scans.
CREATE TEMP TABLE registration_existing_nameplate AS
SELECT nodeid::text nodeid,meterno::text meterno,metercategory::text metercategory,metertemplateid,blockcaptureperiod
FROM __SCHEMA__.nameplate WHERE nodeid::text IN(SELECT nodeid FROM registration_source) OR meterno::text IN(SELECT serial FROM registration_source);
CREATE INDEX ON registration_existing_nameplate(nodeid); CREATE INDEX ON registration_existing_nameplate(meterno);
CREATE TEMP TABLE registration_existing_routing AS
SELECT nodeid::text nodeid,gatewayid::text gatewayid,sinkid::text sinkid
FROM __SCHEMA__.latestrouting WHERE nodeid::text IN(SELECT nodeid FROM registration_source);
CREATE INDEX ON registration_existing_routing(nodeid);
CREATE TEMP TABLE registration_existing_security AS
SELECT meterno::text meterno,masterkey::text masterkey,globalkey::text globalkey,hlsussecret::text hlsussecret,hlsfwsecret::text hlsfwsecret,llsmrsecret::text llsmrsecret
FROM __SCHEMA__.metersecurity WHERE meterno::text IN(SELECT serial FROM registration_source);
CREATE INDEX ON registration_existing_security(meterno);
ANALYZE registration_existing_nameplate; ANALYZE registration_existing_routing; ANALYZE registration_existing_security;
CREATE TEMP TABLE registration_conflicts AS
SELECT s.nodeid,s.serial,
 CASE
 WHEN EXISTS(SELECT 1 FROM registration_existing_nameplate n WHERE (n.nodeid::text=s.nodeid OR n.meterno::text=s.serial) AND
   (n.nodeid::text IS DISTINCT FROM s.nodeid OR n.meterno::text IS DISTINCT FROM s.serial OR n.metercategory::text IS DISTINCT FROM @category OR n.metertemplateid IS DISTINCT FROM @template OR n.blockcaptureperiod IS DISTINCT FROM @period)) THEN 'Existing meter identity/configuration differs'
 WHEN (SELECT count(*) FROM registration_existing_nameplate n WHERE n.nodeid::text=s.nodeid OR n.meterno::text=s.serial)>1 THEN 'Ambiguous existing nameplate'
 WHEN EXISTS(SELECT 1 FROM registration_existing_routing r WHERE r.nodeid::text=s.nodeid AND NOT @preserve AND (r.gatewayid::text IS DISTINCT FROM @gateway OR r.sinkid::text IS DISTINCT FROM @sink)) THEN 'Existing gateway/sink differs'
 WHEN (SELECT count(*) FROM registration_existing_routing r WHERE r.nodeid::text=s.nodeid)>1 THEN 'Ambiguous existing routing'
 WHEN EXISTS(SELECT 1 FROM registration_existing_security k WHERE k.meterno::text=s.serial AND (k.masterkey::text IS DISTINCT FROM 'AAAAAAAAAAAAAAAA' OR k.globalkey::text IS DISTINCT FROM 'AAAAAAAAAAAAAAAA' OR k.hlsussecret::text IS DISTINCT FROM 'AAAAAAAAAAAAAAAA' OR k.hlsfwsecret::text IS DISTINCT FROM 'AAAAAAAAAAAAAAAA' OR k.llsmrsecret::text IS DISTINCT FROM '12345678')) THEN 'Existing security differs'
 WHEN (SELECT count(*) FROM registration_existing_security k WHERE k.meterno::text=s.serial)>1 THEN 'Ambiguous existing security'
 END AS reason
FROM registration_source s;
DELETE FROM registration_conflicts WHERE reason IS NULL;
CREATE TEMP TABLE registration_eligible AS SELECT s.* FROM registration_source s LEFT JOIN registration_conflicts c USING(nodeid) WHERE c.nodeid IS NULL;
CREATE UNIQUE INDEX ON registration_eligible(nodeid);
CREATE UNIQUE INDEX ON registration_eligible(serial);
ANALYZE registration_eligible;
SELECT * FROM registration_conflicts ORDER BY nodeid;
SELECT count(*) AS eligible,
 count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM registration_existing_nameplate n WHERE n.meterno::text=s.serial)) AS new_nameplates,
 count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM registration_existing_security k WHERE k.meterno::text=s.serial)) AS new_security,
 count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM registration_existing_routing r WHERE r.nodeid::text=s.nodeid)) AS new_routing
FROM registration_eligible s;


