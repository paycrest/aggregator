-- Check users whose scope contains 'provider'
SELECT id, email, scope FROM users WHERE scope LIKE '%provider%';