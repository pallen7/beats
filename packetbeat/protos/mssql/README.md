# Microsoft SQL Server protocol parsing for packetbeat

 - The MS-TDS specifications can be found [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds).
 - The version used for this implementation is v28.0 - TDS V7.4. The [Product Behaviour](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/135d0ebe-5c4c-4a94-99bf-1811eccb9f4a) indicates support Microsoft SQL Server 2012+ and .NET Framework 4.8+

This is a Work In Progress. The implementation has been tested against:
 - SQL Server 2019
 - Dotnet core 3.5 test harness
 - [go-mssqldb](https://github.com/denisenkom/go-mssqldb) test harness

Usage & implementation notes:
 - Some clients (i.e. go-mssqldb) send Stored Procedure calls as SQLBatch calls not RPC calls. Dotnet core 3.5 sent stored procedure calls as RPC calls so Proc Name and params could be captured
 - SSMS sends a CEKTable element even when COLUMNENCRYPTION is not being actively used on any columns (see section 2.2.7.4 of the spec) - _"This table MUST be sent when COLUMNENCRYPTION is negotiated by client and server and is turned on"_. This means that to parse the column metadata we need to capture whether COLUMNENCRYPTION is negotiated at logon and persist this data for the lifetime of the connection. The expectation is that a 0x0000 CEKTable will be present if column encryption has been negotiated.  

## TODO
 - Add support for remaining Data types
 - Add support for remaining Token types
 - Add tests
 - Extra field support:
  - List column names / types in datasets?
  - List parameters on RPC input?
  - Return values?
  - In the case of errors still publish a result and populate error notes
 - Fully support column encryption?
 
## Bugs: