import jwt
import time
import uuid

# Retrieves x5c cert chain array from config string
def get_x5c_chain(cert):
    sp = cert.split('-----BEGIN CERTIFICATE-----\n')
    sp = sp[1:]
    
    ca_chain = []
    for ca in sp:
        ca_sp = ca.split('\n-----END CERTIFICATE-----')
        ca_chain.append(ca_sp[0].replace('\n',''))
        
    return ca_chain

# Build JWT from response, encode and sign
def build_signed_jwt(conf, payload, payload_name, aud):

    # Build return object
    result = {}

    result['iss'] = conf['client']['id']
    result['sub'] = conf['client']['id']
    result['aud'] = aud

    iat = int(str(time.time()).split('.')[0])
    exp = iat + 60000
    result['iat'] = iat
    result['exp'] = exp

    result['jti'] = str(uuid.uuid4())

    header = {
        'x5c': get_x5c_chain(conf['client']['crt'])
    }

    # Append payload
    result[payload_name] = payload

    token = jwt.encode(result, conf['client']['key'], algorithm="RS256", headers=header)
    return token
