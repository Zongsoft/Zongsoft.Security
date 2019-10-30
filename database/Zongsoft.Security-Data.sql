/* 添加系统内置角色 */
INSERT INTO Security_Role (RoleId, Name, FullName, Description) VALUES (1, 'Administrators', 'Administrators', '系统管理角色(系统内置角色)');
INSERT INTO Security_Role (RoleId, Name, FullName, Description) VALUES (2, 'Security', 'Security', '安全管理角色(系统内置角色)');

/* 添加系统内置用户 */
INSERT INTO Security_User (UserId, Name, FullName, Description, Status) VALUES (1, 'Administrator', 'Administrator', '系统管理员(系统内置帐号)', 0);
INSERT INTO Security_User (UserId, Name, FullName, Description, Status) VALUES (2, 'Guest', 'Guest', '来宾', 1);

/* 添加系统内置保留名字 */
INSERT INTO Security_Censorship (Name, Word) VALUES ('Names', 'Zongsoft');

/* 添加非法关键字 */
INSERT INTO Security_Censorship (Name, Word) VALUES ('Sensitives', 'fuck');
INSERT INTO Security_Censorship (Name, Word) VALUES ('Sensitives', 'bitch');
