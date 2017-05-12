package br.com.commons.util;

import java.io.FileInputStream;
import java.util.Properties;

public class PropertiesManager {

	private static Properties properties;
	// TODO change to general.config later
	private static String path = "general.test.config";

	public static String getProperty(String property) {
		try {
			if (properties == null) {
				properties = new Properties();
				FileInputStream file = new FileInputStream(path);
				properties.load(file);
			}
		} catch (Exception e) {
			System.out.println("Não foi possível carregar arquivo de propeties");
		}

		return properties.getProperty(property);
	}

	public static void setNewPath(String newpath) {
		path = newpath;
		properties = null;
	}
}
