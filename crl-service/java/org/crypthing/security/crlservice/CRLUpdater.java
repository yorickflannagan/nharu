package org.crypthing.security.crlservice;


import org.crypthing.security.LogDevice;

public abstract class CRLUpdater implements Runnable {

	protected static long MIN_WAIT_TIME = 30000;
	protected static LogDevice log = new LogDevice(CRLUpdater.class.getName());
	private Thread t;  
	private boolean running = true;
	public void init()
	{
		t = new Thread(this);
		t.setDaemon(true);
		t.setName("CRLUpdater");
		t.start();
		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable(){@Override public void run(){running = false;}}));
	}
	
	@Override
	public void run() {
		while(running)
		{
			try { 
				if(running)Thread.sleep(update());
			}
			catch(Exception e) 
			{ 
				log.error("Erro ao atualizar o CRLValidator com o " + this.getClass().getName(), e); 
				try {if(running)Thread.sleep(MIN_WAIT_TIME);} catch (InterruptedException e1) { /* */ }
			}
		}
	}
	
	public boolean isAlive()
	{
		return t.isAlive();
	}
	public abstract long update() throws Exception;
	

}
