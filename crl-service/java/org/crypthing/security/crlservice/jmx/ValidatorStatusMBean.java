package org.crypthing.security.crlservice.jmx;

import java.util.Date;

public interface ValidatorStatusMBean {

	Date getNextUpdate();
	Date getLastUpdate();
	boolean isAlive();
	String listStatus();
	
}
