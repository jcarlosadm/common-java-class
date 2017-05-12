package br.com.commons.util;

import java.io.FileInputStream;
import java.util.Properties;

public class PropertiesManager {

	private static Properties properties;
	private static String path = "general.config";

	public static String getProperty(String property) {
		try {
			if (properties == null) {
				properties = new Properties();
				FileInputStream file = new FileInputStream(path);
				properties.load(file);
			}
		} catch (Exception e) {
			System.out.println("error to load properties file");
		}

		return properties.getProperty(property);
	}

	public static void setNewPath(String newpath) {
		path = newpath;
		properties = null;
	}
}
