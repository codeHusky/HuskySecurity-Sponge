package com.codehusky.huskysecurity.password;

import com.codehusky.huskysecurity.HuskySecurity;
import org.spongepowered.api.entity.living.player.Player;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by lokio on 12/20/2016.
 */
public class PasswordManager {
    private HuskySecurity hs;
    public PasswordManager(HuskySecurity sd){
        this.hs = sd;
    }
    public String hashPassword(String password,Player plr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(!hs.passSalts.containsKey(plr.getUniqueId())) {
            hs.passSalts.put(plr.getUniqueId(), BCrypt.gensalt(10,SecureRandom.getInstanceStrong()));
            hs.updateSalts();
        }
        return BCrypt.hashpw(password,hs.passSalts.get(plr.getUniqueId())).replace(hs.passSalts.get(plr.getUniqueId()),"");
    }
}
