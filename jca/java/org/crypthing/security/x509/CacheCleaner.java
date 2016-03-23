package org.crypthing.security.x509;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.crypthing.util.NharuArray;
import org.crypthing.security.LogDevice;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;
import static org.crypthing.security.LogDevice.LOG_LEVEL_WARNING;
import static org.crypthing.security.LogDevice.LOG_LEVEL_ERROR;


class CacheCleaner extends Thread
{
	private static final String MSG_RUN = "CacheCleaner is now running";
	private static final String MSG_PARAMETERS = "CacheCleaner was loaded with parameters:\n";
	private static final String INFO_INTERRUPTED = "CacheCleaner interrupted";
	private static final LogDevice LOG = new LogDevice(CacheCleaner.class.getName());

	private final Map<NharuArray, NharuX509Certificate> cache;
	private final int watermark;
	private final int lowWatermark;
	private final long timeout;
	private boolean isRunning;

	CacheCleaner(final Map<NharuArray, NharuX509Certificate> cache, final int maxSize, final int minSize, final long timeout)
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG)
		{
			final StringBuilder builder = new StringBuilder();
			builder.append(MSG_PARAMETERS);
			builder.append("maxSize = ");
			builder.append(maxSize);
			builder.append(", minSize = ");
			builder.append(minSize);
			builder.append(" and timeout = ");
			builder.append(timeout);
			LOG.trace(builder.toString());
		}
		this.cache = cache;
		watermark = maxSize;
		lowWatermark = minSize;
		this.timeout = timeout;
		setDaemon(true);
	}
	void shutDown() { isRunning = false; }

	@Override
	public void run()
	{
		if (LOG_LEVEL < LOG_LEVEL_WARNING) LOG.info(MSG_RUN);
		isRunning = true;
		try
		{
			while (isRunning)
			{
				if (cache.size() > watermark)
				{
					final Iterator<Entry<NharuArray, NharuX509Certificate>> set = cache.entrySet().iterator();
					while (set.hasNext() && cache.size() > lowWatermark)
					{
						final Entry<NharuArray, NharuX509Certificate> it = set.next();
						final NharuX509Certificate entry = it.getValue();
						if (entry.takeCota() < 0)
						{
							set.remove();
							entry.closeHandle();
						}
					}
				}
				try { Thread.sleep(timeout); }
				catch (final InterruptedException e)
				{
					isRunning = false;
					e.printStackTrace();
				}
				if (cache.size() == 0) isRunning = false;
			}
		}
		finally
		{
			if (LOG_LEVEL < LOG_LEVEL_ERROR) LOG.warning(INFO_INTERRUPTED);
			NharuX509Factory.blackHawkIsDown();
		}
	}
}
