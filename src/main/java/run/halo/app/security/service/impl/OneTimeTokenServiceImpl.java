package run.halo.app.security.service.impl;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import run.halo.app.cache.AbstractStringCacheStore;
import run.halo.app.security.service.OneTimeTokenService;
import run.halo.app.utils.HaloUtils;

/**
 * One-time token service implementation.
 *
 * @author johnniang
 */
@Service
public class OneTimeTokenServiceImpl implements OneTimeTokenService {

    private static final String tokenPrefix = "OTT-";

    private static final Duration OTT_EXPIRATION_TIME = Duration.ofMinutes(5);

    private static final Duration GRACE_PERIOD = Duration.ofSeconds(5);

    private final AbstractStringCacheStore cacheStore;

    public OneTimeTokenServiceImpl(AbstractStringCacheStore cacheStore) {
        this.cacheStore = cacheStore;
    }

    @Override
    public Optional<String> get(String oneTimeToken) {
        Assert.hasText(oneTimeToken, "One-time token must not be blank");

        // Get token from cache store
        String cacheKey = tokenPrefix + oneTimeToken;
        String tokenState = cacheStore.get(cacheKey).orElse(null);

        if (tokenState == null) {
            return Optional.empty();
        }

        // Parse the token value in "status:uri:timestamp" format
        String[] parts = tokenState.split(":");
        if (parts.length != 3) {
            return Optional.empty();
        }

        String status = parts[0];
        String uri = parts[1];
        long timestamp = Long.parseLong(parts[2]);

        long currentTime = System.currentTimeMillis();

        if ("unused".equals(status)) {
            // Mark OTT as used and update timestamp
            String updatedTokenState = "used:" + uri + ":" + currentTime;
            cacheStore.put(cacheKey, updatedTokenState, OTT_EXPIRATION_TIME.getSeconds(), TimeUnit.SECONDS);
            return Optional.of(uri);
        }

        if ("used".equals(status) && (currentTime - timestamp <= GRACE_PERIOD.toMillis())) {
            // Allow token usage within the grace period
            return Optional.of(uri);
        }

        return Optional.empty();
    }

    @Override
    public String create(String uri) {
        Assert.hasText(uri, "Request uri must not be blank");

        // Generate ott
        String oneTimeToken = HaloUtils.randomUUIDWithoutDash();

        // Create token value in "unused:uri:timestamp" format
        String tokenValue = "unused:" + uri + ":0";

        // Put ott with unused mark and timestamp
        cacheStore.put(tokenPrefix + oneTimeToken,
            tokenValue,
            OTT_EXPIRATION_TIME.getSeconds(),
            TimeUnit.SECONDS);

        // Return ott
        return oneTimeToken;
    }

    @Override
    public void revoke(String oneTimeToken) {
        Assert.hasText(oneTimeToken, "One-time token must not be blank");

        // Delete the token
        cacheStore.delete(tokenPrefix + oneTimeToken);
    }
}
