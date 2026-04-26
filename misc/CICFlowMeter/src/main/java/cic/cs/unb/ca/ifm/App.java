package cic.cs.unb.ca.ifm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
	public static final Logger logger = LoggerFactory.getLogger(App.class);

	public static void main(String[] args) {
		logger.info("GUI entry has been replaced by the command-line interface.");
		Cmd.main(args);
	}
}
