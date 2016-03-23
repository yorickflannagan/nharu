package org.crypthing.security.x509;

final class CleanerShutDown extends Thread
{
	private final CacheCleaner cleaner;
	CleanerShutDown(final CacheCleaner ref) { cleaner = ref; }
	@Override public void run() { cleaner.shutDown(); }
}
