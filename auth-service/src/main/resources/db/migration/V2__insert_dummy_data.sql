-- Insert dummy data for testing
-- Password: Test@1234 (BCrypt hashed)

-- Customer User
INSERT INTO users (user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role, status, email_verified)
VALUES (
    'CUST001',
    'Budi Santoso',
    'budi.santoso@example.com',
    '08123456789',
    '$2a$10$dXJ3SW6G7P50eS6DmwzkCOYz6TtxMQJqhN8/LewY5YmMxSL0S7jey', -- Test@1234
    '1234567890123456',
    'Jl. Merdeka No. 123, Jakarta',
    '1990-05-15',
    'CUSTOMER',
    'ACTIVE',
    TRUE
);

-- Admin User
INSERT INTO users (user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role, status, email_verified)
VALUES (
    'ADMIN001',
    'Siti Nurhaliza',
    'siti.admin@example.com',
    '08234567890',
    '$2a$10$dXJ3SW6G7P50eS6DmwzkCOYz6TtxMQJqhN8/LewY5YmMxSL0S7jey', -- Test@1234
    '2345678901234567',
    'Jl. Sudirman No. 456, Jakarta',
    '1988-03-20',
    'ADMIN',
    'ACTIVE',
    TRUE
);

-- Teller User
INSERT INTO users (user_code, full_name, email, phone_number, password_hash, nik, address, date_of_birth, role, status, email_verified)
VALUES (
    'TELLER001',
    'Ahmad Wijaya',
    'ahmad.teller@example.com',
    '08345678901',
    '$2a$10$dXJ3SW6G7P50eS6DmwzkCOYz6TtxMQJqhN8/LewY5YmMxSL0S7jey', -- Test@1234
    '3456789012345678',
    'Jl. Gatot Subroto No. 789, Jakarta',
    '1992-07-10',
    'TELLER',
    'ACTIVE',
    TRUE
);

