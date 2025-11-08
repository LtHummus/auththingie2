create table webauthn_keys
(
    id                       TEXT              not null
        constraint webauthn_keys_pk
            primary key,
    user_id                  TEXT              not null,
    friendly_name            TEXT                      ,
    last_used                INTEGER default 0 not null,
    public_key               TEXT              not null,
    attestation_type         TEXT              not null,
    transports               TEXT              not null,
    flags                    INTEGER           not null,
    aaguid                   TEXT              not null,
    sign_count               INTEGER default 0 not null,
    clone_warning            INTEGER default 0 not null,
    authenticator_attachment TEXT              not null,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

create index webauthn_keys_user_id_index
    on webauthn_keys (user_id);

create unique index webauthn_keys_public_key_unique_index on webauthn_keys(public_key);

