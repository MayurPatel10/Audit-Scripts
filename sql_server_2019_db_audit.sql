/**********************************************************************************************
 MS SQL SERVER EFFECTIVE-ACCESS AUDIT SCRIPT  (v2.0 -- merged)
 ------------------------------------------------------------------------------------------------
 Purpose : Audit "effective access" -- not just reported access -- per the database blind spots
           described in "The Database Blind Spot" (ISACA NA 2026, Heimdall Data).
 Lineage : Merges SQL_Server_-_Working.sql (v1.0, proven architecture -- cursor + TRY/CATCH,
           validated against a live SQL Server 2022 instance) with the additional coverage in
           sql_server_2019_db_audit.sql (SoD checks, stale-account review, guest-account check,
           column-level grants, human-readable execution-context labels).
 Fixes applied vs. the two source scripts (see inline "FIX:" comments for each):
   1. v1 Section 6b schema-ownership filter had a missing-parentheses OR bug that silently
      defeated the NOT IN exclusion, producing ~12 rows of fixed-role noise PER DATABASE.
   2. v1 Section 8a (EXECUTE AS) had no is_ms_shipped filter, surfacing dozens of Microsoft's
      own system objects (Data Collector, Policy-Based Management, etc.) as false findings.
   3. v2019 Section F2 (synonym boundary check) has an unbalanced-quote LIKE pattern that will
      not parse; replaced with v1's proven PARSENAME-based approach.
   4. v2019 Section J2 (SoD: owner + data access) did not scope the data-access check to the
      OWNED schema, over-flagging any schema owner with any unrelated grant anywhere in the DB.
   5. v2019 Section L2 (guest account) calls HAS_PERMS_BY_NAME with no impersonation, which
      checks the CALLER's permission, not guest's own grant. Replaced with a direct grant check.
   6. v2019 hardcodes a database name, a username, and an audit-file path in four places,
      requiring manual editing before each run. All replaced with instance-wide, unattended logic.
   7. v2019 relies on the undocumented sp_MSforeachdb throughout. Replaced with v1's explicit,
      permission-checked cursor + per-database TRY/CATCH.
 Scope   : On-prem / IaaS SQL Server 2016+. Read-only. No writes, no DDL, no config changes.
 Run as  : sysadmin (or at minimum VIEW SERVER STATE + VIEW ANY DEFINITION + db access).
           WARNING: SQL Server FILTERS metadata by caller permission. Verify your rights with
           Section 0 before trusting any output from a lower-privileged account.
 Testing : This has NOT been executed against a live instance. Run it in non-production first.
 Sections:
   0.  Auditor self-check
   1.  Server principals & authentication surface (+ expiry/lockout flags)
   2.  Server-level role membership -- recursive, with fixed-role risk labels
   3.  Server-level explicit permissions
   4.  PER-DATABASE LOOP (cursor, TRY/CATCH):
       4a. Contained users, user inventory, orphaned users, guest-account check
       4b. Database role membership -- recursive
       4c. Explicit permissions incl. column-level grants and explicit DENY flag
       4d. Object/schema ownership (bug-fixed) + individual-vs-service-account heuristic
       4e. Execution context (EXECUTE AS) with human-readable label + IMPERSONATE
       4f. Segregation-of-duties checks (read+write, owner+access [scope-fixed], svc+DDL)
       4g. Synonyms crossing a database/server boundary (PARSENAME-based)
   5.  Ownership chaining risk: TRUSTWORTHY, DB_CHAINING, cross-db chaining, Service Broker
   6.  SQL Agent proxies, credentials, authorized principals
   7.  Linked servers & login mappings
   8.  Live session identity-substitution check (real-time signal)
   9.  Stale / dormant privileged-account review
   10. Security-relevant configuration snapshot (drift baseline)
   11. SQL Server Audit specification presence + content (path-safe, no hardcoded file path)
   12. Recent permission/DDL changes from the default trace (short-window drift signal)
   Appendix. Targeted effective-permission drill-down (fn_my_permissions), parameterized
**********************************************************************************************/

SET NOCOUNT ON;

---------------------------------------------------------------------------------------------
-- SECTION 0: AUDITOR SELF-CHECK
-- If IS_SRVROLEMEMBER('sysadmin') = 0, every later section may be silently under-reporting.
---------------------------------------------------------------------------------------------
SELECT
    SUSER_SNAME()                            AS run_as_login,
    ORIGINAL_LOGIN()                         AS original_login,
    IS_SRVROLEMEMBER('sysadmin')             AS am_i_sysadmin,
    HAS_PERMS_BY_NAME(NULL,NULL,'VIEW SERVER STATE')    AS can_view_server_state,
    HAS_PERMS_BY_NAME(NULL,NULL,'VIEW ANY DEFINITION')  AS can_view_any_definition,
    @@SERVERNAME                             AS server_name,
    SERVERPROPERTY('ProductVersion')         AS version,
    SYSDATETIMEOFFSET()                      AS audit_timestamp;

---------------------------------------------------------------------------------------------
-- SECTION 1: SERVER PRINCIPALS & AUTHENTICATION SURFACE
-- Merged: v1's base inventory + v2019's expiry/complexity/lockout flags.
---------------------------------------------------------------------------------------------
SELECT
    p.name,
    p.type_desc,
    p.is_disabled,
    p.create_date,
    p.modify_date,
    l.is_policy_checked,
    l.is_expiration_checked,
    LOGINPROPERTY(p.name,'PasswordLastSetTime') AS pwd_last_set,
    CASE WHEN p.type = 'S' THEN LOGINPROPERTY(p.name,'IsExpired') END AS pwd_is_expired,
    CASE WHEN p.type = 'S' THEN LOGINPROPERTY(p.name,'IsLocked')  END AS is_locked,
    CASE WHEN p.type = 'S' AND l.is_expiration_checked = 0 THEN 'RISK: no expiry policy' ELSE '' END AS expiry_flag,
    CASE WHEN p.type = 'S' AND l.is_policy_checked = 0     THEN 'RISK: no complexity policy' ELSE '' END AS complexity_flag
FROM sys.server_principals p
LEFT JOIN sys.sql_logins l ON l.principal_id = p.principal_id
WHERE p.type NOT IN ('R')
  AND p.name NOT LIKE '##%'
ORDER BY p.type_desc, p.name;

---------------------------------------------------------------------------------------------
-- SECTION 2: SERVER ROLE MEMBERSHIP -- RECURSIVE, with fixed-role risk labels
-- Merged: v1's recursive CTE (proven correct) + v2019's risk-level labeling (B4).
---------------------------------------------------------------------------------------------
;WITH RoleChain AS (
    SELECT rm.role_principal_id, rm.member_principal_id,
           CAST(SUSER_NAME(rm.role_principal_id) AS nvarchar(4000)) AS role_path,
           1 AS depth
    FROM sys.server_role_members rm
    UNION ALL
    SELECT rm.role_principal_id, rc.member_principal_id,
           CAST(SUSER_NAME(rm.role_principal_id) + N' -> ' + rc.role_path AS nvarchar(4000)),
           rc.depth + 1
    FROM sys.server_role_members rm
    JOIN RoleChain rc ON rm.member_principal_id = rc.role_principal_id
)
SELECT
    SUSER_NAME(rc.member_principal_id) AS member_name,
    mp.type_desc                       AS member_type,
    rc.role_path                       AS effective_role_chain,
    rc.depth,
    CASE
        WHEN rc.role_path LIKE '%sysadmin%'      THEN 'CRITICAL: full server control'
        WHEN rc.role_path LIKE '%securityadmin%' THEN 'HIGH: can grant server-level access'
        WHEN rc.role_path LIKE '%serveradmin%'   THEN 'HIGH: can change server config'
        WHEN rc.role_path LIKE '%dbcreator%'     THEN 'MEDIUM: can create/alter databases'
        ELSE 'LOW'
    END AS risk_level
FROM RoleChain rc
JOIN sys.server_principals mp ON mp.principal_id = rc.member_principal_id
WHERE mp.type <> 'R'
ORDER BY CASE WHEN rc.role_path LIKE '%sysadmin%' THEN 0 ELSE 1 END, rc.role_path, member_name;

---------------------------------------------------------------------------------------------
-- SECTION 3: SERVER-LEVEL EXPLICIT PERMISSIONS
-- Grants that bypass roles entirely. CONTROL SERVER / IMPERSONATE ANY LOGIN = sysadmin in disguise.
---------------------------------------------------------------------------------------------
SELECT
    SUSER_NAME(sp.grantee_principal_id) AS grantee,
    gp.type_desc                        AS grantee_type,
    sp.permission_name,
    sp.state_desc,
    SUSER_NAME(sp.grantor_principal_id) AS grantor
FROM sys.server_permissions sp
JOIN sys.server_principals gp ON gp.principal_id = sp.grantee_principal_id
WHERE sp.permission_name NOT IN ('CONNECT SQL')
ORDER BY CASE sp.permission_name WHEN 'CONTROL SERVER' THEN 0
                                 WHEN 'IMPERSONATE ANY LOGIN' THEN 1 ELSE 2 END,
         grantee;

---------------------------------------------------------------------------------------------
-- SECTIONS 4a-4g run PER DATABASE via an explicit cursor (v1 architecture -- proven).
-- HAS_DBACCESS filters to only databases the caller can actually reach; TRY/CATCH means one
-- inaccessible or errored database does not abort the run.
---------------------------------------------------------------------------------------------
IF OBJECT_ID('tempdb..#db_users')      IS NOT NULL DROP TABLE #db_users;
IF OBJECT_ID('tempdb..#db_roles')      IS NOT NULL DROP TABLE #db_roles;
IF OBJECT_ID('tempdb..#db_perms')      IS NOT NULL DROP TABLE #db_perms;
IF OBJECT_ID('tempdb..#ownership')     IS NOT NULL DROP TABLE #ownership;
IF OBJECT_ID('tempdb..#exec_as')       IS NOT NULL DROP TABLE #exec_as;
IF OBJECT_ID('tempdb..#impersonate')   IS NOT NULL DROP TABLE #impersonate;
IF OBJECT_ID('tempdb..#synonyms')      IS NOT NULL DROP TABLE #synonyms;
IF OBJECT_ID('tempdb..#orphans')       IS NOT NULL DROP TABLE #orphans;
IF OBJECT_ID('tempdb..#guest_check')   IS NOT NULL DROP TABLE #guest_check;
IF OBJECT_ID('tempdb..#sod_readwrite') IS NOT NULL DROP TABLE #sod_readwrite;
IF OBJECT_ID('tempdb..#sod_owner')     IS NOT NULL DROP TABLE #sod_owner;
IF OBJECT_ID('tempdb..#sod_svc_ddl')   IS NOT NULL DROP TABLE #sod_svc_ddl;

CREATE TABLE #db_users    (db sysname, user_name sysname, user_type nvarchar(60),
                           authentication_type_desc nvarchar(60), is_contained bit,
                           create_date datetime, mapped_login sysname NULL);
CREATE TABLE #db_roles    (db sysname, member_name sysname, member_type nvarchar(60),
                           role_chain nvarchar(4000), depth int);
CREATE TABLE #db_perms    (db sysname, grantee sysname, grantee_type nvarchar(60),
                           class_desc nvarchar(60), securable nvarchar(512), column_name sysname NULL,
                           permission_name nvarchar(128), state_desc nvarchar(60),
                           is_explicit_deny bit);
CREATE TABLE #ownership   (db sysname, finding nvarchar(60), schema_name sysname NULL,
                           object_name sysname NULL, owner_name sysname, type_desc nvarchar(60) NULL,
                           owner_is_individual bit);
CREATE TABLE #exec_as     (db sysname, schema_name sysname, module_name sysname,
                           module_type nvarchar(60), execution_context nvarchar(300));
CREATE TABLE #impersonate (db sysname, grantee sysname, target_principal sysname,
                           state_desc nvarchar(60));
CREATE TABLE #synonyms    (db sysname, schema_name sysname, synonym_name sysname,
                           base_object nvarchar(1035), crosses_boundary bit);
CREATE TABLE #orphans     (db sysname, user_name sysname, user_sid varbinary(85), issue nvarchar(200),
                           schemas_owned int, objects_owned int);
CREATE TABLE #guest_check (db sysname, guest_has_connect bit);
CREATE TABLE #sod_readwrite (db sysname, principal sysname, object_name sysname, finding nvarchar(100));
CREATE TABLE #sod_owner     (db sysname, principal sysname, owned_schema sysname, finding nvarchar(200));
CREATE TABLE #sod_svc_ddl   (db sysname, principal sysname, permission_name sysname, state_desc nvarchar(60), finding nvarchar(100));

DECLARE @db sysname, @sql nvarchar(max);
DECLARE dbs CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.databases
    WHERE state_desc = 'ONLINE'
      AND is_read_only = 0
      AND HAS_DBACCESS(name) = 1
      AND name NOT IN ('tempdb');            -- master/msdb stay IN scope: Agent proxies and
                                              -- built-in service accounts live in msdb.

OPEN dbs;
FETCH NEXT FROM dbs INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'USE ' + QUOTENAME(@db) + N';

    -- 4a: users, contained-user flag, orphan detection (+ schemas/objects owned by orphans)
    INSERT INTO #db_users
    SELECT DB_NAME(), dp.name, dp.type_desc, dp.authentication_type_desc,
           CASE WHEN dp.authentication_type_desc = ''DATABASE'' THEN 1 ELSE 0 END,
           dp.create_date, sp.name
    FROM sys.database_principals dp
    LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
    WHERE dp.type IN (''S'',''U'',''G'')
      AND dp.name NOT IN (''dbo'',''guest'',''sys'',''INFORMATION_SCHEMA'');

    INSERT INTO #orphans
    SELECT DB_NAME(), dp.name, dp.sid,
           CASE WHEN sp.sid IS NULL THEN ''ORPHANED - no matching server login''
                WHEN sp.name <> dp.name THEN ''SID matches login '' + sp.name + '' (name mismatch)''
           END,
           (SELECT COUNT(*) FROM sys.schemas s2 WHERE s2.principal_id = dp.principal_id),
           (SELECT COUNT(*) FROM sys.objects o2 JOIN sys.schemas s3 ON o2.schema_id = s3.schema_id
                WHERE s3.principal_id = dp.principal_id)
    FROM sys.database_principals dp
    LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
    WHERE dp.type IN (''S'',''U'',''G'')
      AND dp.authentication_type_desc = ''INSTANCE''   -- contained users cannot be "orphaned" this way
      AND dp.name NOT IN (''dbo'',''guest'',''sys'',''INFORMATION_SCHEMA'')
      AND (sp.sid IS NULL OR sp.name <> dp.name);

    -- FIX (vs v2019 L2): check guest''s OWN grant directly rather than the caller''s permission.
    INSERT INTO #guest_check
    SELECT DB_NAME(),
           CASE WHEN EXISTS (
               SELECT 1 FROM sys.database_permissions p
               JOIN sys.database_principals dpg ON p.grantee_principal_id = dpg.principal_id
               WHERE dpg.name = ''guest'' AND p.permission_name = ''CONNECT'' AND p.state = ''G''
           ) THEN 1 ELSE 0 END;

    -- 4b: database role membership -- recursive
    ;WITH RC AS (
        SELECT rm.role_principal_id, rm.member_principal_id,
               CAST(USER_NAME(rm.role_principal_id) AS nvarchar(4000)) AS chain, 1 AS depth
        FROM sys.database_role_members rm
        UNION ALL
        SELECT rm.role_principal_id, rc.member_principal_id,
               CAST(USER_NAME(rm.role_principal_id) + N'' -> '' + rc.chain AS nvarchar(4000)),
               rc.depth + 1
        FROM sys.database_role_members rm
        JOIN RC rc ON rm.member_principal_id = rc.role_principal_id )
    INSERT INTO #db_roles
    SELECT DB_NAME(), USER_NAME(rc.member_principal_id), mp.type_desc, rc.chain, rc.depth
    FROM RC rc
    JOIN sys.database_principals mp ON mp.principal_id = rc.member_principal_id
    WHERE mp.type <> ''R'';

    -- 4c: explicit permissions incl. column-level grants and explicit DENY flag
    -- (merged: v1 base + v2019 D3/D4 column-level and DENY additions)
    INSERT INTO #db_perms
    SELECT DB_NAME(),
           USER_NAME(dp.grantee_principal_id),
           gp.type_desc,
           dp.class_desc,
           COALESCE(
             CASE dp.class_desc
               WHEN ''OBJECT_OR_COLUMN'' THEN OBJECT_SCHEMA_NAME(dp.major_id) + ''.'' + OBJECT_NAME(dp.major_id)
               WHEN ''SCHEMA''           THEN SCHEMA_NAME(dp.major_id)
               WHEN ''DATABASE''         THEN DB_NAME()
             END, CONVERT(nvarchar(30), dp.major_id)),
           CASE WHEN dp.class_desc = ''OBJECT_OR_COLUMN'' AND dp.minor_id > 0
                THEN COL_NAME(dp.major_id, dp.minor_id) END,
           dp.permission_name, dp.state_desc,
           CASE WHEN dp.state = ''D'' THEN 1 ELSE 0 END
    FROM sys.database_permissions dp
    JOIN sys.database_principals gp ON gp.principal_id = dp.grantee_principal_id
    WHERE dp.permission_name <> ''CONNECT'';

    -- 4d: object/schema ownership
    -- FIX (vs v1 6b): the original had an unparenthesized OR that made the NOT IN exclusion
    -- meaningless, flooding results with every fixed-role''s self-owned schema. Corrected below.
    INSERT INTO #ownership (db, finding, schema_name, object_name, owner_name, type_desc, owner_is_individual)
    SELECT DB_NAME(), ''OBJECT_OWNER_OVERRIDE'', SCHEMA_NAME(o.schema_id), o.name,
           USER_NAME(o.principal_id), o.type_desc,
           CASE WHEN USER_NAME(o.principal_id) NOT IN (''dbo'') AND o.type_desc <> ''SQL_STORED_PROCEDURE'' THEN 1 ELSE 0 END
    FROM sys.objects o
    WHERE o.principal_id IS NOT NULL
      AND o.is_ms_shipped = 0;

    INSERT INTO #ownership (db, finding, schema_name, object_name, owner_name, type_desc, owner_is_individual)
    SELECT DB_NAME(), ''SCHEMA_OWNED_BY_NON_DBO'', s.name, NULL, USER_NAME(s.principal_id), NULL,
           CASE WHEN USER_NAME(s.principal_id) NOT LIKE ''%svc%'' AND USER_NAME(s.principal_id) NOT LIKE ''%service%''
                THEN 1 ELSE 0 END
    FROM sys.schemas s
    WHERE USER_NAME(s.principal_id) <> ''dbo''
      AND s.name NOT IN (''sys'',''INFORMATION_SCHEMA'',''guest'')
      AND s.name <> USER_NAME(s.principal_id);   -- FIX: proper single AND chain, no dangling OR

    -- 4e: execution context (EXECUTE AS) -- human-readable label, MS-shipped objects excluded
    -- FIX (vs v1 8a): added is_ms_shipped = 0 (was missing; caused ~50 system-proc false rows).
    -- FIX (vs v2019 E1): true CALLER context is NULL, not 0; OWNER sentinel is -2, not treated
    -- as a magic literal without explanation. Both are labeled explicitly below.
    INSERT INTO #exec_as
    SELECT DB_NAME(), OBJECT_SCHEMA_NAME(m.object_id), OBJECT_NAME(m.object_id), o.type_desc,
           CASE
               WHEN m.execute_as_principal_id = -2 THEN ''OWNER (dynamic -- resolves to current object owner at runtime)''
               ELSE ''EXPLICIT: '' + ISNULL(USER_NAME(m.execute_as_principal_id), ''(unresolvable principal_id '' + CONVERT(varchar(10), m.execute_as_principal_id) + '')'')
           END
    FROM sys.sql_modules m
    JOIN sys.objects o ON o.object_id = m.object_id
    WHERE m.execute_as_principal_id IS NOT NULL     -- NULL = true CALLER context; excluded here
      AND o.is_ms_shipped = 0;

    INSERT INTO #impersonate
    SELECT DB_NAME(), USER_NAME(dp.grantee_principal_id),
           USER_NAME(dp.major_id), dp.state_desc
    FROM sys.database_permissions dp
    WHERE dp.permission_name = ''IMPERSONATE'';

    -- 4f: Segregation-of-duties checks (new vs v1; corrected vs v2019)
    -- f1: same principal has both read and write on the same object
    INSERT INTO #sod_readwrite
    SELECT DB_NAME(), r.grantee, r.object_name, ''HAS BOTH SELECT AND INSERT/UPDATE/DELETE''
    FROM (
        SELECT USER_NAME(p.grantee_principal_id) AS grantee,
               OBJECT_NAME(p.major_id)           AS object_name,
               MAX(CASE WHEN p.permission_name = ''SELECT'' THEN 1 ELSE 0 END) AS has_read,
               MAX(CASE WHEN p.permission_name IN (''INSERT'',''UPDATE'',''DELETE'') THEN 1 ELSE 0 END) AS has_write
        FROM sys.database_permissions p
        WHERE p.class = 1
        GROUP BY p.grantee_principal_id, p.major_id
    ) r
    WHERE r.has_read = 1 AND r.has_write = 1;

    -- f2: principal owns a schema AND independently holds a data-access grant ON AN OBJECT
    -- WITHIN THAT SAME SCHEMA. FIX (vs v2019 J2): original EXISTS check was unscoped and would
    -- match ANY grant anywhere in the database, not specifically within the owned schema.
    INSERT INTO #sod_owner
    SELECT DB_NAME(), dp.name, s.name,
           ''REVIEW: owns schema AND holds direct data-access grant on an object within it''
    FROM sys.database_principals dp
    JOIN sys.schemas s ON s.principal_id = dp.principal_id
    WHERE dp.type NOT IN (''R'',''A'')
      AND s.name NOT IN (''dbo'',''guest'',''sys'',''INFORMATION_SCHEMA'')
      AND EXISTS (
        SELECT 1
        FROM sys.database_permissions p
        JOIN sys.objects o ON p.major_id = o.object_id AND p.class = 1
        WHERE p.grantee_principal_id = dp.principal_id
          AND p.permission_name IN (''SELECT'',''INSERT'',''UPDATE'',''DELETE'')
          AND o.schema_id = s.schema_id
      );

    -- f3: name-pattern-matched service accounts holding DDL-altering rights
    -- NOTE: name-pattern matching is a weak heuristic -- naming conventions vary by org.
    -- Treat this as a starting point, not a definitive finding list.
    INSERT INTO #sod_svc_ddl
    SELECT DB_NAME(), USER_NAME(p.grantee_principal_id), p.permission_name, p.state_desc,
           ''REVIEW: name-pattern-matched service account can alter code objects''
    FROM sys.database_permissions p
    JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
    WHERE p.permission_name IN (''CREATE PROCEDURE'',''ALTER ANY OBJECT'',''CONTROL'',''ALTER'',
                                 ''CREATE FUNCTION'',''CREATE VIEW'',''CREATE TRIGGER'')
      AND (dp.name LIKE ''%svc%'' OR dp.name LIKE ''%app%'' OR dp.name LIKE ''%service%'');

    -- 4g: synonyms crossing a database/server boundary
    -- FIX (vs v2019 F2): that version''s LIKE pattern has an unbalanced quote and will not
    -- parse. This uses v1''s PARSENAME approach, which is syntactically correct and was
    -- validated against real data (correctly found a cross-database synonym in prior runs).
    INSERT INTO #synonyms
    SELECT DB_NAME(), SCHEMA_NAME(sn.schema_id), sn.name, sn.base_object_name,
           CASE WHEN PARSENAME(sn.base_object_name, 3) IS NOT NULL
                 AND PARSENAME(sn.base_object_name, 3) <> DB_NAME() THEN 1
                WHEN PARSENAME(sn.base_object_name, 4) IS NOT NULL THEN 1
                ELSE 0 END
    FROM sys.synonyms sn;
    ';
    BEGIN TRY
        EXEC sp_executesql @sql;
    END TRY
    BEGIN CATCH
        PRINT 'Skipped database [' + @db + ']: ' + ERROR_MESSAGE();
    END CATCH;
    FETCH NEXT FROM dbs INTO @db;
END
CLOSE dbs; DEALLOCATE dbs;

SELECT * FROM #db_users      ORDER BY db, user_name;
SELECT * FROM #db_users      WHERE is_contained = 1 ORDER BY db;          -- contained users: bypass server-level login controls entirely
SELECT * FROM #db_roles      ORDER BY db, role_chain, member_name;
SELECT * FROM #db_perms      ORDER BY db, grantee, securable;
SELECT * FROM #db_perms      WHERE is_explicit_deny = 1 ORDER BY db;      -- explicit DENY overrides any role GRANT -- easy to miss
SELECT * FROM #ownership     ORDER BY db, finding, schema_name;
SELECT * FROM #exec_as       ORDER BY db, schema_name, module_name;
SELECT * FROM #impersonate   ORDER BY db, grantee;
SELECT * FROM #synonyms      WHERE crosses_boundary = 1 ORDER BY db;
SELECT * FROM #orphans       ORDER BY db, schemas_owned DESC, objects_owned DESC, user_name;
SELECT * FROM #guest_check   WHERE guest_has_connect = 1;                 -- SOX/PCI finding if any rows returned
SELECT * FROM #sod_readwrite ORDER BY db, principal;
SELECT * FROM #sod_owner     ORDER BY db, principal;
SELECT * FROM #sod_svc_ddl   ORDER BY db, principal;

---------------------------------------------------------------------------------------------
-- SECTION 5: OWNERSHIP CHAINING RISK -- TRUSTWORTHY, DB_CHAINING, Service Broker
-- TRUSTWORTHY + db owned by sysadmin = any db_owner can escalate to sysadmin.
-- KNOWN LIMITATION: IS_SRVROLEMEMBER('sysadmin', <name>) only reliably resolves principals
-- registered as their OWN server principal. If the owner is an individual account that only
-- inherits sysadmin via a Windows GROUP login (e.g., BUILTIN\Administrators), this check can
-- return NULL/false even though the account is effectively sysadmin. Cross-reference the
-- Section 2 recursive role-chain output for the owner's name before concluding "OK".
---------------------------------------------------------------------------------------------
SELECT
    d.name AS db,
    SUSER_SNAME(d.owner_sid)   AS db_owner_login,
    d.is_trustworthy_on,
    d.is_db_chaining_on,
    d.is_broker_enabled,
    CASE WHEN d.is_trustworthy_on = 1
          AND IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)) = 1
          AND d.name <> 'msdb'
         THEN 'HIGH: TRUSTWORTHY db owned by sysadmin (per IS_SRVROLEMEMBER) -- db_owner can escalate to sysadmin'
         WHEN d.is_trustworthy_on = 1 AND d.name <> 'msdb'
         THEN 'REVIEW: TRUSTWORTHY enabled -- also manually confirm owner''s effective sysadmin status via Section 2'
         WHEN d.is_db_chaining_on = 1
         THEN 'REVIEW: cross-database ownership chaining enabled'
         ELSE 'OK' END AS risk_note
FROM sys.databases d
ORDER BY CASE WHEN d.is_trustworthy_on = 1 OR d.is_db_chaining_on = 1 THEN 0 ELSE 1 END, d.name;

-- Server-wide cross-db chaining switch
SELECT name, value_in_use
FROM sys.configurations
WHERE name = 'cross db ownership chaining';

-- Server-level IMPERSONATE grants
SELECT
    SUSER_NAME(sp.grantee_principal_id) AS grantee,
    SUSER_NAME(sp.major_id)             AS can_impersonate_login,
    sp.state_desc
FROM sys.server_permissions sp
WHERE sp.permission_name = 'IMPERSONATE';

---------------------------------------------------------------------------------------------
-- SECTION 6: SQL AGENT PROXIES, CREDENTIALS, AUTHORIZED PRINCIPALS
---------------------------------------------------------------------------------------------
SELECT p.name AS proxy_name, c.name AS credential_name, c.credential_identity AS runs_as_identity,
       p.enabled
FROM msdb.dbo.sysproxies p
JOIN sys.credentials c ON c.credential_id = p.credential_id;

SELECT p.name AS proxy_name,
       CASE WHEN l.sid IS NULL THEN '(all sysadmins -- no specific principal row)' ELSE SUSER_SNAME(l.sid) END AS authorized_principal
FROM msdb.dbo.sysproxies p
JOIN msdb.dbo.sysproxylogin l ON l.proxy_id = p.proxy_id;

SELECT credential_id, name, credential_identity, create_date, modify_date
FROM sys.credentials;

---------------------------------------------------------------------------------------------
-- SECTION 7: LINKED SERVERS & LOGIN MAPPINGS (cross-boundary + identity substitution)
---------------------------------------------------------------------------------------------
SELECT
    s.name              AS linked_server,
    s.product, s.provider, s.data_source,
    s.is_data_access_enabled,
    s.is_rpc_out_enabled,
    CASE WHEN ll.local_principal_id = 0 THEN '<ALL OTHER LOGINS>'
         ELSE SUSER_SNAME(lp.sid) END          AS local_login,
    ll.uses_self_credential,
    ll.remote_name                              AS maps_to_remote_login,
    CASE WHEN ll.local_principal_id = 0 AND ll.remote_name IS NOT NULL
         THEN 'HIGH: every local login shares one fixed remote identity'
         WHEN ll.uses_self_credential = 0 AND ll.remote_name IS NOT NULL
         THEN 'REVIEW: identity substitution on remote system'
         ELSE 'OK/self' END                     AS risk_note
FROM sys.servers s
LEFT JOIN sys.linked_logins ll ON ll.server_id = s.server_id
LEFT JOIN sys.server_principals lp ON lp.principal_id = ll.local_principal_id
WHERE s.is_linked = 1
ORDER BY s.name;

---------------------------------------------------------------------------------------------
-- SECTION 8: LIVE SESSION IDENTITY-SUBSTITUTION CHECK (real-time signal, new vs v1)
-- A session where login_name differs from original_login_name is running under a different
-- identity than the one that authenticated -- EXECUTE AS or an app-level proxy is in effect.
---------------------------------------------------------------------------------------------
SELECT
    s.session_id, s.login_name AS authenticated_login, s.original_login_name AS original_login,
    s.nt_user_name, s.status, s.login_time, s.program_name,
    CASE WHEN s.login_name <> s.original_login_name
         THEN 'ALERT: identity substituted (EXECUTE AS / impersonation in effect right now)'
         ELSE 'Normal' END AS identity_flag
FROM sys.dm_exec_sessions s
WHERE s.is_user_process = 1
ORDER BY identity_flag DESC, s.session_id;

---------------------------------------------------------------------------------------------
-- SECTION 9: STALE / DORMANT PRIVILEGED-ACCOUNT REVIEW (new vs v1)
-- Same IS_SRVROLEMEMBER limitation noted in Section 5 applies to the privilege_tier column
-- below for Windows-group-inherited membership; treat as a lead, not a definitive result.
---------------------------------------------------------------------------------------------
SELECT
    sp.name, sp.type_desc, sp.create_date,
    LOGINPROPERTY(sp.name,'LastSuccessfulLogon') AS last_login,
    LOGINPROPERTY(sp.name,'IsLocked')            AS is_locked,
    sp.is_disabled,
    CASE WHEN IS_SRVROLEMEMBER('sysadmin', sp.name) = 1
              OR IS_SRVROLEMEMBER('securityadmin', sp.name) = 1
              OR IS_SRVROLEMEMBER('serveradmin', sp.name) = 1
         THEN 'PRIVILEGED' ELSE 'standard' END AS privilege_tier
FROM sys.server_principals sp
WHERE sp.type IN ('S','U')
  AND sp.is_disabled = 0
  AND (LOGINPROPERTY(sp.name,'LastSuccessfulLogon') IS NULL
       OR LOGINPROPERTY(sp.name,'LastSuccessfulLogon') < DATEADD(DAY,-90,GETDATE()))
ORDER BY privilege_tier DESC, last_login;

---------------------------------------------------------------------------------------------
-- SECTION 10: SECURITY-RELEVANT CONFIGURATION SNAPSHOT (drift baseline)
-- Merged superset of both scripts' configuration lists, with v2019's inline severity notes.
---------------------------------------------------------------------------------------------
SELECT
    c.name AS config_name, c.value_in_use, c.minimum, c.maximum,
    CASE c.name
        WHEN 'xp_cmdshell'                   THEN CASE WHEN c.value_in_use = 1 THEN 'CRITICAL: OS command execution from T-SQL' ELSE 'OK' END
        WHEN 'Ole Automation Procedures'     THEN CASE WHEN c.value_in_use = 1 THEN 'HIGH: COM object access' ELSE 'OK' END
        WHEN 'Ad Hoc Distributed Queries'    THEN CASE WHEN c.value_in_use = 1 THEN 'HIGH: OPENROWSET/OPENDATASOURCE enabled' ELSE 'OK' END
        WHEN 'remote access'                 THEN CASE WHEN c.value_in_use = 1 THEN 'REVIEW: legacy remote SP execution enabled' ELSE 'OK' END
        WHEN 'cross db ownership chaining'   THEN CASE WHEN c.value_in_use = 1 THEN 'HIGH: cross-DB privilege chains enabled server-wide' ELSE 'OK' END
        WHEN 'common criteria compliance enabled' THEN CASE WHEN c.value_in_use = 0 THEN 'INFORMATIONAL: C2-style audit mode off' ELSE 'OK' END
        WHEN 'clr enabled'                   THEN CASE WHEN c.value_in_use = 1 THEN 'REVIEW: CLR integration enabled' ELSE 'OK' END
        WHEN 'external scripts enabled'      THEN CASE WHEN c.value_in_use = 1 THEN 'REVIEW: R/Python execution enabled' ELSE 'OK' END
        WHEN 'scan for startup procs'        THEN CASE WHEN c.value_in_use = 1 THEN 'REVIEW: startup-marked procs auto-execute on service start' ELSE 'OK' END
        ELSE 'Informational'
    END AS audit_note
FROM sys.configurations c
WHERE c.name IN (
    'xp_cmdshell','clr enabled','clr strict security','Ad Hoc Distributed Queries',
    'cross db ownership chaining','Database Mail XPs','Ole Automation Procedures',
    'remote access','remote admin connections','scan for startup procs',
    'external scripts enabled','common criteria compliance enabled',
    'contained database authentication')
ORDER BY audit_note, config_name;

---------------------------------------------------------------------------------------------
-- SECTION 11: SQL SERVER AUDIT SPECIFICATION PRESENCE + CONTENT
-- FIX (vs v2019 I3/I4): those queries hardcode a lab-specific audit-file path (C:\Students\...)
-- and will error if it doesn't exist. This discovers the ACTUAL configured path first and only
-- queries it if an enabled audit is found.
---------------------------------------------------------------------------------------------
SELECT
    sa.name AS server_audit_name, sa.is_state_enabled, sa.type_desc AS audit_destination,
    sfa.log_file_path, sfa.log_file_name, sa.on_failure_desc,
    ss.name AS audit_spec_name, ss.is_state_enabled AS spec_enabled
FROM sys.server_audits sa
LEFT JOIN sys.server_file_audits sfa ON sa.audit_id = sfa.audit_id   -- FIX: path/name only exist here, not on sys.server_audits; NULL for APPLICATION_LOG/SECURITY_LOG destinations
LEFT JOIN sys.server_audit_specifications ss ON sa.audit_guid = ss.audit_guid
ORDER BY sa.name;

DECLARE @audit_log_path NVARCHAR(500);
SELECT TOP 1 @audit_log_path = sfa.log_file_path
FROM sys.server_audits sa
JOIN sys.server_file_audits sfa ON sa.audit_id = sfa.audit_id   -- FIX: only file-destination audits have a path fn_get_audit_file can read
WHERE sa.is_state_enabled = 1
ORDER BY sa.audit_id;   -- if multiple enabled audits exist, inspect the query above and adjust

IF @audit_log_path IS NOT NULL
BEGIN
    SELECT TOP 200
        event_time, server_principal_name AS actor, database_name, object_name, statement,
        action_id, succeeded
    FROM sys.fn_get_audit_file(@audit_log_path + N'*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIF','G','GWG','D','RV','DPGR','AL','CR','DR')
    ORDER BY event_time DESC;
END
ELSE
    PRINT 'No enabled SQL Server Audit found -- relying on the default-trace section below for a shorter-window signal.';

---------------------------------------------------------------------------------------------
-- SECTION 12: RECENT SECURITY/DDL CHANGES FROM THE DEFAULT TRACE (drift signal, short window)
-- The default trace rolls over quickly (5 x 20MB files) -- this is a SIGNAL, not full history.
---------------------------------------------------------------------------------------------
DECLARE @trc nvarchar(520);
SELECT @trc = REVERSE(SUBSTRING(REVERSE(path), CHARINDEX(N'\', REVERSE(path)), 520)) + N'log.trc'
FROM sys.traces WHERE is_default = 1;

IF @trc IS NOT NULL
BEGIN
    SELECT
        te.name AS event_name, t.StartTime, t.LoginName AS performed_by,
        t.SessionLoginName AS original_session_login,
        t.DatabaseName, t.ObjectName, t.TargetLoginName, t.RoleName, t.TextData
    FROM ::fn_trace_gettable(@trc, DEFAULT) t
    JOIN sys.trace_events te ON te.trace_event_id = t.EventClass
    WHERE te.name IN (
        'Audit Add Login Event','Audit Add DB User Event',
        'Audit Add Member to DB Role Event','Audit Add Login to Server Role Event',
        'Audit Database Scope GDR Event','Audit Schema Object GDR Event',
        'Audit Server Scope GDR Event',
        'Object:Created','Object:Altered','Object:Deleted',
        'Audit Database Principal Impersonation Event',
        'Audit Server Principal Impersonation Event')
    ORDER BY t.StartTime DESC;
END
ELSE
    PRINT 'Default trace not available -- use SQL Server Audit / Extended Events for change history.';

/**********************************************************************************************
 APPENDIX: TARGETED EFFECTIVE-PERMISSION DRILL-DOWN (fn_my_permissions)
 ------------------------------------------------------------------------------------------------
 This asks the ENGINE to resolve a specific principal's effective permissions directly --
 the most literal answer to "reported access vs. effective access." It is NOT run automatically
 across every user (that would require impersonating each one in turn, which is slow and
 intrusive); use it as a deliberate drill-down on principals flagged as high-risk above
 (e.g., anyone in #sod_owner, or a member of a role identified in Section 2/9).

 Fill in the two variables below and run this block manually, once per principal of interest.
**********************************************************************************************/
/*
USE [TargetDatabase];   -- <-- set to the database containing the principal
GO
DECLARE @target_user SYSNAME = N'TargetPrincipal';   -- <-- set to the principal to evaluate

EXECUTE AS USER = @target_user;
    SELECT entity_name, subentity_name, permission_name
    FROM fn_my_permissions(NULL, 'DATABASE')
    ORDER BY permission_name, entity_name;
REVERT;
GO
*/

/**********************************************************************************************
 END OF SCRIPT -- Suggested workflow (maps to the presentation's 6-step model):
 1. Run the full script, export each result set to your workpaper (baseline capture).
 2. Re-run on a schedule; diff Sections 2, 4b, 4c, 4d, 4e, 5, 6, 7 against the baseline (drift).
 3. Treat Sections 5, 4e, 4f, 6, 7 findings as "effective access" evidence -- these are the
    paths that never appear in a standard grant-table export.
 4. Use the Appendix drill-down to confirm effective access for any principal flagged above.
**********************************************************************************************/