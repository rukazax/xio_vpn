package app.xio.labreceiver;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Arrays;
/** Lab-only recipient: checks FileProvider read grant; never saves keys. */
public class Receiver extends Activity {
 @Override public void onCreate(Bundle state){super.onCreate(state);TextView text=new TextView(this);text.setTextSize(20);text.setPadding(24,40,24,24);setContentView(text);
 try{
  Uri uri=getIntent().getParcelableExtra(Intent.EXTRA_STREAM);
  if(uri==null||!"app.xio.xio.profiles".equals(uri.getAuthority()))throw new Exception();
  if((getIntent().getFlags()&Intent.FLAG_GRANT_READ_URI_PERMISSION)==0)throw new Exception();
  ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];
  try(InputStream input=getContentResolver().openInputStream(uri)){int n;while((n=input.read(buffer))!=-1){out.write(buffer,0,n);if(out.size()>200000)throw new Exception();}}
  String raw=new String(out.toByteArray(),"UTF-8");if(!(raw.startsWith("x1o://")||raw.startsWith("xio://")))throw new Exception();
  JSONObject j=new JSONObject(new String(Base64.decode(raw.substring(6),Base64.URL_SAFE),"UTF-8"));
  HashSet<String> keys=new HashSet<>();java.util.Iterator<String> it=j.keys();while(it.hasNext())keys.add(it.next());
  if(!keys.equals(new HashSet<>(Arrays.asList("schema","name","userId","serverId","configs"))))throw new Exception();
  if(j.getInt("schema")!=1)throw new Exception();JSONObject configs=j.getJSONObject("configs");if(configs.length()!=4)throw new Exception();
  if(!configs.getString("awg").contains("PrivateKey = ")||!configs.getString("wireguard").contains("PrivateKey = "))throw new Exception();
  for(String protocol:Arrays.asList("rivet-h3","rivet-s1")){JSONObject cfg=new JSONObject(configs.getString(protocol));if(!cfg.getString("protocol").equals(protocol)||!cfg.getString("id").equals(j.getString("userId"))||Base64.decode(cfg.getString("secret"),Base64.DEFAULT).length!=32||Base64.decode(cfg.getString("entryToken"),Base64.DEFAULT).length!=32)throw new Exception();}
  text.setText("XIO_PROFILE_OK\nWireGuard + AmneziaWG + RIVET H3/S1\nNo administrator credentials\nCross-app read grant verified\nNo keys saved by recipient");
 }catch(Exception error){text.setText("XIO_PROFILE_FAILED");}
 }
}
