import { Base64 } from 'js-base64'
import CryptoJS from 'crypto'
import Env from '@ioc:Adonis/Core/Env'

export const decryptLaravelCrypto = async (crypto: string) => {
    if(crypto){
        let b64 = Base64.decode(crypto)
        let json = JSON.parse(b64.toString())
        let iv: Buffer = Buffer.from(json.iv, 'base64')
        let value: Buffer = Buffer.from(json.value, 'base64')

        const laravelKey: String = Env.get('LARAVEL_KEY')
        const key: Buffer = Buffer.from(laravelKey, 'base64')

        const decipher = CryptoJS.createDecipheriv("aes-256-cbc", key, iv)

        let decrypted = decipher.update(value) + decipher.final('utf-8')
        
        const subDecrypted = decrypted.substr(10, decrypted.length)

        return subDecrypted
    }
}
