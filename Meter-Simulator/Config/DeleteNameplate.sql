DECLARE @MeterCount INT = 100; 
DECLARE @StartIndex INT = 1;

DECLARE @i INT = @StartIndex;

WHILE @i < @StartIndex + @MeterCount
BEGIN
    DECLARE @MeterNo VARCHAR(20) = 'MTR' + RIGHT('00000' + CAST(@i AS VARCHAR), 5);

    DECLARE @NodeId VARCHAR(20) = CAST(10000000 + @i AS VARCHAR); 

    DELETE FROM [LatestRouting]
    WHERE NodeId = @NodeId;

    DELETE FROM [MeterSecurity]
    WHERE MeterNo = @MeterNo;

    DELETE FROM [NamePlate]
    WHERE MeterNo = @MeterNo;

    SET @i = @i + 1;
END