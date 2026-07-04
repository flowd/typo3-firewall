CREATE TABLE tx_firewall_event (
    uid int(11) unsigned NOT NULL auto_increment,
    event_type varchar(32) DEFAULT '' NOT NULL,
    rule varchar(255) DEFAULT '' NOT NULL,
    ban_type varchar(16) DEFAULT '' NOT NULL,
    key_hash varchar(64) DEFAULT '' NOT NULL,
    key_display varchar(255) DEFAULT '' NOT NULL,
    request_host varchar(255) DEFAULT '' NOT NULL,
    request_path varchar(2048) DEFAULT '' NOT NULL,
    request_method varchar(10) DEFAULT '' NOT NULL,
    user_agent varchar(255) DEFAULT '' NOT NULL,
    meta text,
    created_at int(11) unsigned DEFAULT '0' NOT NULL,

    PRIMARY KEY (uid),
    KEY event_type_created_at (event_type, created_at),
    KEY created_at (created_at)
);
