package cic.cs.unb.ca.ifm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CICFlowMeter {

	public static final Logger logger = LoggerFactory.getLogger(CICFlowMeter.class);
	public static void main(String[] args) {
		logger.info("Legacy entry has been redirected to the command-line interface.");
		Cmd.main(args);
	}
}
