# Jolin Tasks
Features in charge and status of final implementation.

## Data Security Features
1. Data Retention Policy
    - Specifies how long data should be stored
    - Ensures that data cannot be deleted or overwritten until they reach the age defined in the retention policy
    - Retroactively applies to existing objects in the bucket as well as new objects added to the bucket.
    - Post and Media Files with last modified date more than 365 days will be moved to archive bucket
    - Post and Media Files with last modified date more than 730 days will be deleted
    - Policy scheduled to run every 24 hours
    
<br/>

2. Integrity Control
    - To ensure data has not been tampered with during transit, data will be hashed before transit and compared to data hashed after transit. 
    - If the hash matches, then we know that the integrity of the data is intact.
    - Hashing Algorithm: SHA256
    
<br/>

3. Role Based Access Control
    - There are two types of roles in TTL, Admins and SuperAdmins, with SuperAdmins having all the access. 
    - SuperAdmins can edit access rights of Admins, including 'read, 'write' and 'delete' access.
    - SuperAdmins can ban Admins from accessing TTL. Admins will be notified via email that their account has been banned.
    - Only after SuperAdmins unban the Admins account, Admins will have only the ‘read’ access back.
    - Both Admins and SuperAdmins have the ability to add IP addresses they would like to block.  The IP address will then be blacklisted
    - If Identity Proxy detects request with blacklisted IP address, user will not be able to access any resources of TTL.

<br/>


## TomTomLoad Features
1. Role Based Access Page
   - View Admins
   - Create Admins
   - Edit Admins access rights
   - Ban Admins
   - Add IP addresses to blacklist
   - Revoke Certificates

<br/>

2. Error Page
   - Error page will be displayed if request was a malformed or illegal request [400 Bad Request]
   - Error page will be displayed if user is not authorised to access the page [401 Unauthorised]
   - Error page will be displayed if user ido not have permission to access resource [403 Forbidden]
   - Error page will be displayed if resource is not found [404 Not Found]
   - Error page will be displayed if request method is not supported [405 Method Not Allowed]
   - Error page will be displayed if rate limit exceeded [429 Too Many Requests]
   - Error page will be displayed if server encountered an internal error or misconfiguration and is unable to complete request [500 Internal Server Error]
   
<br/>

3. Email
   - Email will be sent to Admins when they are banned from accessing TTL
