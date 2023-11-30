-- auto-generated definition
create table users
(
    id                 text                    not null
        constraint table_name_pk
            primary key,
    username           text                    not null,
    password           text                    not null,
    roles              text       default '[]' not null,
    admin              integer(1) default 0,
    totp_seed          text       default null,
    password_timestamp integer                 not null
);

create unique index table_name_id_uindex
    on users (id);

create unique index table_name_username_uindex
    on users (username);


