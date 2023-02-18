# Sze Yan Tasks
Features in charge and status of final implementation.

## Data Security Features
1.	End Point Verification (zero trust)
    - Collects and reports device inventory information.
    - Use to manage secure access to our TTL server. This can be paired with role based access control for further granularity control.
    - Works with Identity Proxy’s signed headers.
    - As an admin, you can review the device information such as
        - OS type and version
        - SUPER ADMIN certificates
        - User-Agents
        - IP address and location
        - Time
    - All these provide Contextual Aware Access to TTL, by verifying the endpoint devices first. 

<br/>

2.	Certificate Authority (PKI)
    - For additional security, SUPER ADMINs will have to obtain a SUPER ADMIN certificate before granting access to TTL. 
    - Once granted the certificate, the device the user is on, will be registered to that device. 
    - SUPER ADMIN cannot use another device to login.

<br/>

3.	Identity Proxy (zero trust)
    - Establish a central authorisation layer for TTL.
    - Uses Google Single Sign-On (SSO) to provide Authentication and Authorisation. 
    - Authentication
        - ADMINs will be authorised with SSO.
        - SUPER ADMINs will be authorised with SSO if they have a valid SUPER ADMIN certificate.
    - Authorisation (Role Based Access Control)
        - If the request credentials are valid, not blacklisted, the identity proxy will then check the user’s assigned role and authorise the request by adding on signed headers. 
    - Signed headers 
        - TTL-Authenticated-User-Name
        - TTL-JWTAuthenticated-User
        - Uses JSON Web Tokens (JWT) to make sure that a request to your app is authorised. Every authorised request will have the signed headers. 
        - Verifying JWT Header
            - Uses HS256 Algorithm.
            - Keys will be generated using Google Cloud Hardware Security Module Keys.
        - Inside JWT Header
            - Standard JWT properties (iat, issuer)
            - Expiration time (10 mins with skewed time of 1 mins)
            - Email, Role, google_id
    - Redirect to TTL with the signed headers. Only traffic that went through the Identity Proxy will ever reach TTL. 
    - TTL-Context-Aware-Access.

<br/>

4.	Encryption at Rest (Storage)
    - Key Management System using Google Key Management System
        - Create Cryptographic keys using Hardware Security Module (HSM)
        - HSM are tamper-resistant to perform cryptographic operations. 
        - High level of entropy to generate high quality keys 
        - 1 for Identity Proxy JWTkey (symmetric key)
        - 1 for TomTomLoad Post (symmetric key)
    - Key Rotation
        - In the event that a key is compromised, regular rotation limits the number of actual messages vulnerable to compromise.
            - The old key will be destroyed. 
            - Rotated every 90 days. 
    - Encryption using symmetric encryption AES-256-GCM.

<br/>

5.	Data Loss Prevention 
    - De-identifying sensitive data in Post via regular expression.
    - De-identifying sensitive data in Media via OCR with regular expression.
    - Sensitive Data includes
        - Email
        - NRIC
        - Phone
        - IP Address
        - GitHub Auth Token
        - JSON Web Token
        - Credit Card
    - Will be redacted. None of these will be stored. 

<br/>

## TomTomLoad Features
1.	Media and Post Creation
    - View Media Gallery 
    - Upload Media 
    - Delete Media
    - View Posts
    - Create Post with layouts (Headers, move blocks, quotes)
    - Edit Post
    - Delete Post

<br/>

2.	Logging
    - Logging of the valuable information such as
    - Cryptographic Operations – Encryption, Decryption, Decoding
    - Downloading of files from Google Cloud Storage
    - Initialising of Security features – Data Loss Prevention, Data Retention Policy…
    - Errors the server encounters
