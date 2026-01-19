/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.extensions.securityheaders.exclusion;

import java.net.URI;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents an exclusion rule for filtering security header check results.
 * Immutable data class.
 */
public final class ExclusionRule {

	private final String id;
	private final ExclusionRuleType type;
	private final String pattern;

	public ExclusionRule(ExclusionRuleType type, String pattern) {
		this(UUID.randomUUID().toString(), type, pattern);
	}

	public ExclusionRule(String id, ExclusionRuleType type, String pattern) {
		this.id = Objects.requireNonNull(id, "id must not be null");
		this.type = Objects.requireNonNull(type, "type must not be null");
		this.pattern = Objects.requireNonNull(pattern, "pattern must not be null");
	}

	public String getId() {
		return id;
	}

	public ExclusionRuleType getType() {
		return type;
	}

	public String getPattern() {
		return pattern;
	}

	/**
	 * Checks if the given URL matches this exclusion rule.
	 *
	 * @param method
	 *            HTTP method (GET, POST, etc.)
	 * @param url
	 *            Full URL (e.g., https://example.com/api/users)
	 * @return true if the URL should be excluded
	 */
	public boolean matches(String method, String url) {
		switch (type) {
			case HOST :
				return matchesHost(url);
			case PATH :
				return matchesPath(url);
			case ENDPOINT :
				return matchesEndpoint(method, url);
		}
		// Unreachable: all enum cases are covered
		throw new IllegalStateException("Unknown ExclusionRuleType: " + type);
	}

	private boolean matchesHost(String url) {
		String host = extractHost(url);
		return host != null && host.equalsIgnoreCase(pattern);
	}

	private boolean matchesPath(String url) {
		String path = extractPath(url);
		if (path == null) {
			return false;
		}
		// Exact match or prefix match with wildcard support
		if (pattern.endsWith("*")) {
			String prefix = pattern.substring(0, pattern.length() - 1);
			return path.startsWith(prefix);
		}
		return path.equals(pattern);
	}

	private boolean matchesEndpoint(String method, String url) {
		String endpoint = method + " " + url;
		return endpoint.equals(pattern);
	}

	private String extractHost(String url) {
		try {
			URI uri = new URI(url);
			return uri.getHost();
		} catch (Exception e) {
			return null;
		}
	}

	private String extractPath(String url) {
		try {
			URI uri = new URI(url);
			String path = uri.getPath();
			return (path == null || path.isEmpty()) ? "/" : path;
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		ExclusionRule that = (ExclusionRule) o;
		return id.equals(that.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id);
	}

	@Override
	public String toString() {
		return type.getDisplayName() + ": " + pattern;
	}
}
