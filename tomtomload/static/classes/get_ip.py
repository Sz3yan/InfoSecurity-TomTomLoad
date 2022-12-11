import ipinfo

access_token = '9418185c79f1df'
handler = ipinfo.getHandler(access_token)
details = handler.getDetails()

print(details.city)

print(details.loc)
