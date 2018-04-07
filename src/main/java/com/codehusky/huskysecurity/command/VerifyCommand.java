package com.codehusky.huskysecurity.command;

import com.codehusky.huskysecurity.HuskySecurity;
import org.spongepowered.api.command.CommandException;
import org.spongepowered.api.command.CommandResult;
import org.spongepowered.api.command.CommandSource;
import org.spongepowered.api.command.args.CommandContext;
import org.spongepowered.api.command.spec.CommandExecutor;
import org.spongepowered.api.entity.living.player.Player;
import org.spongepowered.api.text.Text;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

/**
 * Created by lokio on 12/20/2016.
 */
public class VerifyCommand implements CommandExecutor {
    private HashMap<UUID,String> verificationHelper = new HashMap<>();
    private HashMap<UUID,Integer> tryCounter = new HashMap<>();
    private HuskySecurity hs;
    public VerifyCommand(HuskySecurity hs){
        this.hs = hs;
    }
    @Override
    public CommandResult execute(CommandSource src, CommandContext args) throws CommandException {
        if(src instanceof Player) {
            Player cause = (Player) src;
            String passed = (String) args.getOne(Text.of("passphrase")).get();
            String hashed = null;
            try {
                hashed = hs.pm.hashPassword(passed,cause);
            } catch (Exception e) {
                e.printStackTrace();
                return CommandResult.empty();
            }
            UUID uid = cause.getUniqueId();
            if(!hs.flagged.contains(uid)){
                //We're not flagged
                String[] aabb = {"changepassword","change","set","setpassword","password"};
                ArrayList<String> changePassword = new ArrayList<>(Arrays.asList(aabb));
                if(passed.equalsIgnoreCase("cancel") && verificationHelper.containsKey(uid)){
                    cause.sendMessage(hs.formatSecurityText("Canceled password change!"));
                    verificationHelper.remove(uid);
                }else if(changePassword.contains(passed.toLowerCase())){
                    if(!hs.passHashes.containsKey(uid) || verificationHelper.containsKey(uid)){
                        if(passed.equalsIgnoreCase("password")){
                            cause.sendMessage(hs.formatSecurityText("You can't use \"password\" as your password."));
                        }else{
                            cause.sendMessage(hs.formatSecurityText("Please finish verifying your password before using subcommands."));
                        }
                    }else{
                        verificationHelper.put(uid,null);
                        cause.sendMessage(hs.formatSecurityText("Please type your new password with /verify."));
                    }
                }else {
                    if (verificationHelper.containsKey(uid)) {
                        if(verificationHelper.get(uid) == null){
                            verificationHelper.put(uid,hashed);
                            cause.sendMessage(hs.formatSecurityText("Please retype your new password with /verify."));
                        }else if(verificationHelper.get(uid).equals(hashed)) {
                            verificationHelper.remove(uid);
                            hs.passHashes.put(uid, hashed);
                            hs.updateConfig();
                            cause.sendMessage(hs.formatSecurityText("Your password has been successfully set."));
                        }else{
                            cause.sendMessage(hs.formatSecurityText("Please try again, or type \"cancel\" instead of your password to cancel the password setting process."));
                        }
                    }else if (!hs.passHashes.containsKey(uid)) {
                        //We don't have a valid password.
                        if (!verificationHelper.containsKey(uid)) {
                            cause.sendMessage(hs.formatSecurityText("Please retype your password for verification with /verify."));
                            verificationHelper.put(uid, hashed);
                        }else if(verificationHelper.get(uid).equals(hashed)) {
                            verificationHelper.remove(uid);
                            hs.passHashes.put(uid, hashed);
                            hs.updateConfig();
                            cause.sendMessage(hs.formatSecurityText("Your password has been successfully set."));
                        }else{
                            cause.sendMessage(hs.formatSecurityText("Please try again, or type \"cancel\" instead of your password to cancel the password setting process."));
                        }
                    }else{
                        cause.sendMessage(hs.formatSecurityText("You're currently considered verified!"));
                    }
                }
            }else{
                //So we're flagged.
                if(hs.passHashes.containsKey(uid)){
                    //User has a password set
                    if(hs.passHashes.get(uid).equals(hashed)) {
                        cause.sendMessage(hs.formatSecurityText("Successfully verified legitimacy!"));
                        hs.flagged.remove(uid);
                    }else{
                        if(!tryCounter.containsKey(uid))
                            tryCounter.put(uid,0);
                        int current = tryCounter.get(uid) + 1;
                        tryCounter.put(uid,current);
                        int remaining = 3 - current;
                        if(remaining > 0) {
                            cause.sendMessage(hs.formatSecurityText("Incorrect passphrase! You have " + remaining + ((remaining > 1) ? " tries" : " try") + " left."));
                        }else{
                            hs.securityCompromised(cause);
                        }
                    }
                }else{
                    //User has no password set.
                    cause.sendMessage(hs.formatSecurityText("Since you did not set a password before you traveled from your regular ip, you are currently unable to use commands without contacting another server administrator."));
                }
            }

        }
        return CommandResult.success();
    }
}
