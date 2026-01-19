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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Manages exclusion rules for security header checks. Thread-safe singleton
 * implementation.
 */
public final class ExclusionRuleManager {

	private static final ExclusionRuleManager INSTANCE = new ExclusionRuleManager();

	private final List<ExclusionRule> rules;
	private final List<Consumer<List<ExclusionRule>>> listeners;

	private ExclusionRuleManager() {
		this.rules = new CopyOnWriteArrayList<>();
		this.listeners = new CopyOnWriteArrayList<>();
	}

	public static ExclusionRuleManager getInstance() {
		return INSTANCE;
	}

	/** Adds a new exclusion rule. */
	public void addRule(ExclusionRule rule) {
		rules.add(rule);
		notifyListeners();
	}

	/** Removes an exclusion rule by its ID. */
	public void removeRule(String ruleId) {
		rules.removeIf(rule -> rule.getId().equals(ruleId));
		notifyListeners();
	}

	/** Updates an existing rule. */
	public void updateRule(String ruleId, ExclusionRuleType newType, String newPattern) {
		for (int i = 0; i < rules.size(); i++) {
			if (rules.get(i).getId().equals(ruleId)) {
				rules.set(i, new ExclusionRule(ruleId, newType, newPattern));
				notifyListeners();
				return;
			}
		}
	}

	/** Gets a rule by its ID. */
	public Optional<ExclusionRule> getRule(String ruleId) {
		return rules.stream().filter(rule -> rule.getId().equals(ruleId)).findFirst();
	}

	/** Returns an unmodifiable view of all rules. */
	public List<ExclusionRule> getRules() {
		return Collections.unmodifiableList(new ArrayList<>(rules));
	}

	/** Clears all exclusion rules. */
	public void clearRules() {
		rules.clear();
		notifyListeners();
	}

	/**
	 * Checks if the given URL should be excluded based on current rules.
	 *
	 * @param method
	 *            HTTP method
	 * @param url
	 *            Full URL
	 * @return true if the URL matches any exclusion rule
	 */
	public boolean shouldExclude(String method, String url) {
		return rules.stream().anyMatch(rule -> rule.matches(method, url));
	}

	/** Adds a listener that will be notified when rules change. */
	public void addChangeListener(Consumer<List<ExclusionRule>> listener) {
		listeners.add(listener);
	}

	/** Removes a change listener. */
	public void removeChangeListener(Consumer<List<ExclusionRule>> listener) {
		listeners.remove(listener);
	}

	private void notifyListeners() {
		List<ExclusionRule> currentRules = getRules();
		for (Consumer<List<ExclusionRule>> listener : listeners) {
			listener.accept(currentRules);
		}
	}
}
