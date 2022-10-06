import { CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = process.env.JWKS_URL
const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJHXibh/DPMD2dMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1pYjBhaXR1dS51cy5hdXRoMC5jb20wHhcNMjIxMDAzMTUxMDQ3WhcN
MzYwNjExMTUxMDQ3WjAkMSIwIAYDVQQDExlkZXYtaWIwYWl0dXUudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsHsgkcHFafkw3CH4
Shf1YjqPdpcZ+aTyM1+4wMDNPjmZeFBCMHHWMbw5/0yvdktg71GRBfiEUQPcnynd
LugI1b1LltH1iAYZ811LrhUa9O8kfA06Jgb7sjQU/gYhpCCr/LqIYNfx9o/iRAO1
EThXnq3STOvm+gURQrIPGAB7/TjHi24Y/8QAzHS81fXsJSSmyLc68k/WiJhdVvI/
5OD85m3iJv3FJv1dC66Q3atGk0C+c22/vO3aY32L0MVtrd6Lr3Z5YMH9Hq4RtOMT
65XxcWt2F00DZT3QA7mgbpFASXmzuvtQ0ULudkIr9ViDsjKXOqKiXq0XmcLjuthT
gKoMwQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRPXQ9gkDzt
vTyFJAlbciyWzFhsADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AGncZ0S+kzHV+ToqzgTgO8YKe0nXfj28VOR9Yh4hKMVDgRqqXPQRplICpufJKd8y
ISLRyq6b3yvZD2AWxifwpmEnMSwp3H0U5JfIgVViVIFz37DYrgqHqtFEjqok3zEU
8ITRSC3LTDi833bsIPPs5qdpms50MAJzrmuIGaciieewvxMAVxXXzKBYA0g5QVmr
lSbBiP+0Nuct2UGa5aB0ZIGgKLJb2GFc2Cso+WAWNjbTGcdaIrYCXdMiY4nVau1l
lIrfbvr3ARkeoUzFkHu0lKPLMJagKWh7QbLM6gQdH9GL1p5Frhq051u9tThtfRx1
I3Mu/qOP/TvoLCcvp/baDJY=
-----END CERTIFICATE-----`

export const handler = async (
  event
): Promise<CustomAuthorizerResult> => {
  logger.info(event)

  logger.info('Authorizing a user', event.authorizationToken)
  try {

    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt
  // logger.info(jwt)

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  // const cert = await getSigningCertificate(jwt.header.kid)
  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  logger.info(token)
  logger.info(typeof(token))
  // logger.info(decode(token))
  return token
}

// async function getSigningCertificate(kid: string): Promise<string> {
//   try {
//     logger.info('jwksUrl', jwksUrl)

//     const { data: keys } = await Axios.get(jwksUrl)

//     logger.info('jwksUrl response', keys)

//     if (!keys || !keys.length) {
//       throw new Error('The JWKS endpoint did not contain any keys')
//     }

//     const signingKeys = keys
//       .filter(
//         (key) =>
//           key.use === 'sig' &&
//           key.kty === 'RSA' &&
//           key.kid &&
//           ((key.x5c && key.x5c.length) || (key.n && key.e))
//       )
//       .map((key) => {
//         return { kid: key.kid, nbf: key.nbf, publicKey: certToPEM(key.x5c[0]) }
//       })

//     if (!signingKeys.length) {
//       throw new Error(
//         'The JWKS endpoint did not contain any signature verification keys'
//       )
//     }

//     const signingKey = signingKeys.find((key) => key.kid === kid)

//     if (!signingKey) {
//       throw new Error(`Unable to find a signing key that matches '${kid}'`)
//     }

//     return signingKey
//   } catch (err) {
//     logger.error(`Unable to get signing key for token: ${err.message}`)
//     throw new Error(`Unable to get signing key for token: ${err.message}`)
//   }
// }

// function certToPEM(cert) {
//   cert = cert.match(/.{1,64}/g).join('\n')
//   cert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`
//   return cert
// }
