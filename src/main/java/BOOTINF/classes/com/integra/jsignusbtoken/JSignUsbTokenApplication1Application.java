package BOOTINF.classes.com.integra.jsignusbtoken;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.integra.jsignusbtoken.utilities.Properties_Loader;

@SpringBootApplication
public class JSignUsbTokenApplication1Application {

	public static void main(String[] args) {
		SpringApplication.run(JSignUsbTokenApplication1Application.class, args);
		 Properties_Loader.loadProperties();
	}

}
