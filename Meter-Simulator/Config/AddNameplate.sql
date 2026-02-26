DECLARE @MeterCount INT = 1000;
DECLARE @BasePort INT = 4059;
DECLARE @StartIndex INT = 1;

DECLARE @i INT = @StartIndex;

WHILE @i < @StartIndex + @MeterCount
BEGIN
    DECLARE @MeterNo VARCHAR(20) = 'MTR' + RIGHT('00000' + CAST(@i AS VARCHAR), 5);
    DECLARE @NodeId VARCHAR(20) = CAST(10000000 + @i AS VARCHAR);
    DECLARE @DeviceId VARCHAR(30) = 'AKS000' + @MeterNo;
    DECLARE @Port VARCHAR(10) = CAST(@BasePort + (@i - @StartIndex) AS VARCHAR);

    -- NamePlate
    IF NOT EXISTS (SELECT 1 FROM NamePlate WHERE MeterNo = @MeterNo)
    BEGIN
        INSERT INTO [dbo].[NamePlate]
        (
            [Guid],
            [MeterNo],
            [DeviceId],
            [Manufacturer],
            [FirmwareVersion],
            [MeterType],
            [MeterCategory],
            [Rating],
            [YearOfManufacture],
            [CTRatio],
            [PTRatio],
            [CreatedDate],
            [NodeId],
            [MeterTemplateId],
            [Installedon],
            [IP],
            [Port]
        )
        VALUES
        (
            NEWID(),
            @MeterNo,
            @DeviceId,
            'AG',
            'AKS 27.2',
            '6',
            'D1',
            '(5-30) A',
            2026,
            '1',
            '1',
            GETDATE(),
            @NodeId,
            63,
            GETDATE(),
            '127.0.0.1',
            @Port
        );
    END

    -- MeterSecurity
    IF NOT EXISTS (SELECT 1 FROM MeterSecurity WHERE MeterNo = @MeterNo)
    BEGIN
        INSERT INTO [dbo].[MeterSecurity]
        (
            [MeterNo],
            [MasterKey],
            [GlobalKey],
            [HLSUSSecret],
            [HLSFWSecret],
            [LLSMRSecret],
            [CreatedDate],
            [UpdatedDate]
        )
        VALUES
        (
            @MeterNo,
            'AAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAAAAAA',
            '12345678',
            GETDATE(),
            GETDATE()
        );
    END

    -- LatestRouting
    IF NOT EXISTS (SELECT 1 FROM [LatestRouting] WHERE NodeId = @NodeId)
    BEGIN
        INSERT INTO [dbo].[LatestRouting]
        (
            [CreatedDate],
            [NodeId],
            [GatewayId],
            [SinkId],
            [LinkScore],
            [LastCommunicatedOn],
            [SourceEndpoint],
            [HopCount]
        )
        VALUES
        (
            GETUTCDATE(),
            @NodeId,
            'direct_tcp',
            'direct_tcp',
            1,
            GETUTCDATE(),
            1,
            1
        );
    END

    SET @i = @i + 1;
END