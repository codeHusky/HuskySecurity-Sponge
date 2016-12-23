package pw.codehusky.serverdefender.password;

import org.spongepowered.api.entity.living.player.Player;
import org.springframework.security.crypto.bcrypt.BCrypt;
import pw.codehusky.serverdefender.ServerDefender;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by lokio on 12/20/2016.
 */
public class PasswordManager {
    private ServerDefender sd;
    public PasswordManager(ServerDefender sd){
        this.sd = sd;
    }
    public String hashPassword(String password,Player plr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(!sd.passSalts.containsKey(plr.getUniqueId())) {
            sd.passSalts.put(plr.getUniqueId(), BCrypt.gensalt(10,new SecureRandom()));
            sd.updateSalts();
        }
        return BCrypt.hashpw(password,sd.passSalts.get(plr.getUniqueId())).replace(sd.passSalts.get(plr.getUniqueId()),"");
    }
}
