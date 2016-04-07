package org.crypthing.security.crlservice.jmx;

import java.util.Date;

import org.crypthing.security.crlservice.CRLUpdater;
import org.crypthing.security.crlservice.CRLValidator;

public class ValidatorStatus implements ValidatorStatusMBean {

	private Date retorno = new Date();
	
	private CRLUpdater updater;
	
	public ValidatorStatus(CRLUpdater updater)
	{
		this.updater = updater;
	}
	
	@Override
	public Date getNextUpdate() {
		if(CRLValidator.getNextAsTimeMilis() != retorno.getTime()) { retorno = new Date(CRLValidator.getNextAsTimeMilis()); }
		return retorno;
	}

	@Override
	public String listStatus() {
		return CRLValidator.listStatus();
	}

	@Override
	public Date getLastUpdate() {
		return new Date(CRLValidator.getLastUpdate());
	}

	@Override
	public boolean isAlive() {
		return updater.isAlive();
	}

}
