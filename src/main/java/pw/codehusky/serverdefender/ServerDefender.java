package pw.codehusky.serverdefender;

import com.google.common.reflect.TypeToken;
import com.google.inject.Inject;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Subdivision;
import ninja.leaping.configurate.ConfigurationOptions;
import ninja.leaping.configurate.commented.CommentedConfigurationNode;
import ninja.leaping.configurate.loader.ConfigurationLoader;
import org.slf4j.Logger;
import org.spongepowered.api.Sponge;
import org.spongepowered.api.command.args.GenericArguments;
import org.spongepowered.api.command.spec.CommandSpec;
import org.spongepowered.api.config.DefaultConfig;
import org.spongepowered.api.entity.living.player.Player;
import org.spongepowered.api.event.Listener;
import org.spongepowered.api.event.command.SendCommandEvent;
import org.spongepowered.api.event.game.state.GameStartedServerEvent;
import org.spongepowered.api.event.network.ClientConnectionEvent;
import org.spongepowered.api.plugin.Plugin;
import org.spongepowered.api.service.ban.BanService;
import org.spongepowered.api.text.Text;
import org.spongepowered.api.text.format.TextColors;
import org.spongepowered.api.text.title.Title;
import org.spongepowered.api.util.ban.Ban;
import org.spongepowered.api.util.ban.BanTypes;
import pw.codehusky.serverdefender.command.VerifyCommand;
import pw.codehusky.serverdefender.password.PasswordManager;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

/**
 * Created by lokio on 12/20/2016.
 */
@Plugin(id="serverdefender",name = "ServerDefender",version = "1.0-SNAPSHOT",description = "Secure your precious server")
public class ServerDefender {
    @Inject
    private Logger logger;

    @Inject
    @DefaultConfig(sharedRoot = true)
    private ConfigurationLoader<CommentedConfigurationNode> privateConfig;

    public HashMap<UUID,String[]> lastLoginData = new HashMap<>();
    public ArrayList<UUID> flagged = new ArrayList<>();
    public HashMap<UUID,String> passHashes = new HashMap<>();
    public PasswordManager pm = null;
    public Title secNotice = Title.of(Text.of(TextColors.RED, "Security Notice!"),Text.of("Check the chat for more info."));

    private byte[] salt;
    private BanService banService = Sponge.getServiceManager().provide(BanService.class).get();

    @Listener
    public void gameStarted(GameStartedServerEvent event) throws IOException {
        readConfig();
        pm= new PasswordManager(salt);
        salt = null;
        CommandSpec verifSpec = CommandSpec.builder()
                .description(Text.of("Verify administrator accounts"))
                .permission("serverdefender.verify")
                .executor(new VerifyCommand(this))
                .arguments(GenericArguments.string(Text.of("passphrase")))
                .build();

        Sponge.getCommandManager().register(this, verifSpec, "verify");

        logger.info("Running.");
    }
    public void readConfig() {
        try {
            CommentedConfigurationNode cn = privateConfig.load();
            CommentedConfigurationNode lastNode = cn.getNode("lastLoginData");
            for(Object puid : lastNode.getChildrenMap().keySet()){
                UUID uid = UUID.fromString(puid.toString());
                String[] data = lastNode.getNode(puid).getList(TypeToken.of(String.class)).toArray(new String[3]);
                lastLoginData.put(uid,data);
            }
            CommentedConfigurationNode salt = cn.getNode("salt");
            if(salt.getValue() == null){
                byte[] thing = new byte[16];
                new SecureRandom().nextBytes(thing);
                ByteBuffer wrapped = ByteBuffer.wrap(thing); // big-endian by default
                short num = wrapped.getShort(); // 1
                salt.setValue(num);
                this.salt = thing;
                cn.removeChild("hashes");
                passHashes = new HashMap<>();
            }else{
                int potential = salt.getInt();
                ByteBuffer dbuf = ByteBuffer.allocate(16);
                dbuf.putInt(potential);
                this.salt = dbuf.array();
            }
            if(cn.getNode("hashes").getValue() != null) {
                CommentedConfigurationNode hashNode = cn.getNode("hashes");
                for(Object puid : hashNode.getChildrenMap().keySet()){
                    UUID uid = UUID.fromString(puid.toString());
                    passHashes.put(uid,hashNode.getNode(puid).getString());
                }
            }

            privateConfig.save(cn);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void updateConfig() {
        try {
            ConfigurationOptions co = ConfigurationOptions.defaults().setShouldCopyDefaults(true);
            CommentedConfigurationNode cn = privateConfig.load(co);
            CommentedConfigurationNode lastNode = cn.getNode("lastLoginData");
            for(UUID uid : lastLoginData.keySet()){
                String[] data = lastLoginData.get(uid);
                lastNode.getNode(uid).setValue(Arrays.asList(data));
            }
            cn.getNode("hashes").setValue(passHashes);
            privateConfig.save(cn);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Listener
    public void onConnection(ClientConnectionEvent.Login event) {
        if(flagged.contains(event.getTargetUser().getUniqueId()))
            flagged.remove(event.getTargetUser().getUniqueId());
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            // A File object pointing to your GeoIP2 or GeoLite2 database
            DatabaseReader reader = new DatabaseReader.Builder(classLoader.getResourceAsStream("geodb.mmdb")).build();

            InetAddress ipAddress = event.getConnection().getAddress().getAddress();

            CityResponse response = reader.city(ipAddress);

            Country country = response.getCountry();
            Subdivision subdivision = response.getMostSpecificSubdivision();
            if(lastLoginData.containsKey(event.getTargetUser().getUniqueId())){
                Object[] past = lastLoginData.get(event.getTargetUser().getUniqueId());
                if(!past[0].equals(ipAddress.getHostAddress())||
                        !past[1].equals(country.getIsoCode())||
                        !past[2].equals(subdivision.getIsoCode())){
                    flagged.add(event.getTargetUser().getUniqueId());
                }
            }else{
                String[] past = {ipAddress.getHostAddress(),country.getIsoCode(),subdivision.getIsoCode()};
                lastLoginData.put(event.getTargetUser().getUniqueId(),past);
                updateConfig();
            }
        }catch(Exception e){
            flagged.add(event.getTargetUser().getUniqueId());
        }


    }
    @Listener
    public void onLoad(ClientConnectionEvent.Join event){
        Player plr = event.getTargetEntity();
        if(flagged.contains(plr.getUniqueId())) {
            event.setMessageCancelled(true);
            Sponge.getServer().getBroadcastChannel().send(event.getMessage());
            sendSecurityNotice("Your locati" +
                    "on is strange, verify your identity with /verify!",plr);
        }else if(!passHashes.containsKey(plr.getUniqueId())){
            event.setMessageCancelled(true);
            Sponge.getServer().getBroadcastChannel().send(event.getMessage());
            sendSecurityNotice("Please set a password with /verify",plr);
        }
    }
    @Listener
    public void onDisconnect(ClientConnectionEvent.Auth event){
        logger.info(event.getOriginalMessage().toPlain());
    }
    @Listener
    public void onCommand(SendCommandEvent event){
        if(event.getCommand().toLowerCase().contains("verify ") || event.getCommand().equalsIgnoreCase("verify"))
            return;

        if(event.getCause().root() instanceof Player){
            Player plr = ((Player) event.getCause().root()).getPlayer().get();
            if(flagged.contains(plr.getUniqueId())) {
                if (plr.hasPermission("serverdefender.verify")) {
                    if (event.getCommand().toLowerCase().contains("op ") || event.getCommand().equalsIgnoreCase("op")) {
                        securityCompromised(plr);
                        event.setCancelled(true);
                    }else {
                        sendSecurityNotice("Please verify your account with /verify ",plr);
                        event.setCancelled(true);
                    }
                }
            }else if(!passHashes.containsKey(plr.getUniqueId())){
                sendSecurityNotice("Please set a password with /verify",plr);
                event.setCancelled(true);
            }

        }

    }
    public void securityCompromised(Player player){
        Ban ourBan = Ban.builder()
                .reason(Text.of(TextColors.RED, "Your account has been automatically banned over a detected compromise.", TextColors.RESET, "\n\nPlease verify your ownership with the owner of the server as soon as possible."))
                .type(BanTypes.PROFILE)
                .profile(player.getProfile())
                .build();
        banService.addBan(ourBan);
        player.kick(ourBan.getReason().get());
    }
    public void sendSecurityNotice(Object content,Player target){
        target.sendTitle(secNotice);
        target.sendMessage(formatSecurityText(content));
    }
    public Text formatSecurityText(Object content){
        return Text.of(TextColors.RED,"ServerDefender",TextColors.GRAY, ": ",TextColors.RESET, content);
    }

}
