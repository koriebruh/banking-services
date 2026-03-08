docker exec -it account-postgres psql -U account_user -d account_db
# SHOW ALL DB
\l

# SHOW ALL TABLES
\dt

# SHOW ALL DATA FROM TABLE
SELECT * FROM account;