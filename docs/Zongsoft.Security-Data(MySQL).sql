INSERT INTO `Security_Role` (`RoleId`, `Name`, `Description`) VALUES (1, 'Administrators', '系统管理角色(系统内置角色)');
INSERT INTO `Security_User` (`UserId`, `Name`, `Description`) VALUES (1, 'Administrator', '系统管理员(系统内置帐号)');
INSERT INTO `Security_User` (`UserId`, `Name`, `Description`) VALUES (2, 'Guest', '；来宾(系统内置帐号)');


INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Automao');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Zongsoft');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'SaaS');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'admin');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'root');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'anonymous');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'everyone');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'system');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Global');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Globals');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Administrator');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Administrators');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Guest');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Guests');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'User');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Users');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Customer');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Customers');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Manager');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Managers');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Moderator');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Moderators');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Editor');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Editors');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Demo');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Demos');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Test');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Tests');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Tester');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Testers');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Service');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Services');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Security');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Names', 'Securities');


INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Sensitives', 'fuck');
INSERT INTO `Security_Censorship` (`Name`, `Word`) VALUES ('Sensitives', 'bitch');
