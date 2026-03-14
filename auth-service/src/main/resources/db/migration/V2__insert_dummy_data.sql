-- =====================================================
-- Seed initial system users
-- Password plaintext: Test@1234
-- Hash: BCrypt (cost 10)
-- =====================================================

-- ADMIN
INSERT INTO users (id, user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role,
                   status,
                   email_verified)
SELECT '00000000-0000-0000-0000-000000000001',
       'ADMIN001',
       'System Administrator',
       'admin@bank.local',
       '08000000001',
       '$2a$10$FMbZSNfnmr3JNS/k9qBLkuduh2cn16HLXoYUfDTPQIBi8/ZdOoe0q',
       '0000000000000001',
       'System Internal',
       '1980-01-01',
       'ADMIN',
       'ACTIVE',
       TRUE WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'admin@bank.local'
);


-- TELLER
INSERT INTO users (id, user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role,
                   status,
                   email_verified)
SELECT '00000000-0000-0000-0000-000000000002',
       'TELLER001',
       'Default Teller',
       'teller@bank.local',
       '08000000002',
       '$2a$10$IYmboxBQpCB2b1sR.oNFqeBC7ldsriilLefoW5Ja5jk40yhrYyfem',
       '0000000000000002',
       'System Internal',
       '1990-01-01',
       'TELLER',
       'ACTIVE',
       TRUE WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'teller@bank.local'
);


-- CUSTOMER (dummy testing user)
INSERT INTO users (id, user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role,
                   status,
                   email_verified)
SELECT '00000000-0000-0000-0000-000000000003',
       'USR-DEMO-1',
       'Maya Kartika Sari',
       'maya.kartika.sari@example.com',
       '08000000003',
       '$2a$10$u9lWFH7VYCLT91Xm01U4r.mxI5sbuJkK/sbX8NLZ.lDtS16/2Gc5m',
       '0000000000000003',
       'Test Address',
       '1995-01-01',
       'CUSTOMER',
       'ACTIVE',
       TRUE WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'customer@bank.local'
);