-- Identity IDs are allocated by the database; existing rows are never updated or deleted.
INSERT INTO __SCHEMA__.nameplate
 (guid,meterno,deviceid,manufacturer,firmwareversion,metertype,metercategory,rating,
 yearofmanufacture,ctratio,ptratio,createddate,nodeid,metertemplateid,installedon,
 originalinstalledon,communicationmodule,blockcaptureperiod,migrationdatetime)
SELECT gen_random_uuid(),s.serial,'MAYA00'||regexp_replace(s.serial,'[^0-9]','','g'),
 'Kushal (Kimbal)','AGXX01',@metertype,@category,'(10-60)A',2025,1,1,
 timezone('UTC',now()),s.nodeid,@template,timezone('UTC',now()),timezone('UTC',now()),
 'MQTT',@period,timezone('UTC',now())
FROM registration_eligible s
WHERE NOT EXISTS(SELECT 1 FROM registration_existing_nameplate n WHERE n.meterno=s.serial);

INSERT INTO __SCHEMA__.metersecurity
 (meterno,masterkey,globalkey,hlsussecret,hlsfwsecret,llsmrsecret,createddate,updateddate)
SELECT s.serial,'AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA',
 '12345678',timezone('UTC',now()),timezone('UTC',now())
FROM registration_eligible s
WHERE NOT EXISTS(SELECT 1 FROM registration_existing_security k WHERE k.meterno=s.serial);

INSERT INTO __SCHEMA__.latestrouting
 (createddate,nodeid,gatewayid,sinkid,linkscore,lastcommunicatedon,sourceendpoint,hopcount,iscommunicating)
SELECT timezone('UTC',now()),s.nodeid,@gateway,@sink,1,timezone('UTC',now()),@endpoint,1,true
FROM registration_eligible s
WHERE NOT EXISTS(SELECT 1 FROM registration_existing_routing r WHERE r.nodeid=s.nodeid);
