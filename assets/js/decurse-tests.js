/**
 * Decurse Antispam - Test Interface
 *
 * Runs spam detection tests and displays results in real-time
 */
(function() {
    'use strict';

    if (typeof decurseTests === 'undefined') {
        return;
    }

    document.addEventListener('DOMContentLoaded', function() {
        initTestInterface();
    });

    function initTestInterface() {
        var runButton = document.getElementById('decurse-run-tests');
        if (!runButton) {
            return;
        }

        runButton.addEventListener('click', runTests);
    }

    function runTests() {
        var runButton = document.getElementById('decurse-run-tests');
        var resultsContainer = document.getElementById('decurse-tests-results');
        var testsList = document.getElementById('decurse-tests-list');
        var progressFill = document.getElementById('tests-progress-fill');
        var progressText = document.getElementById('tests-progress-text');
        var summaryContainer = document.getElementById('decurse-tests-summary');

        // Get selected tests
        var selectedTests = [];

        if (document.querySelector('input[name="test_honeypot"]:checked')) {
            selectedTests.push('honeypot_spam', 'honeypot_valid');
        }
        if (document.querySelector('input[name="test_time"]:checked')) {
            selectedTests.push('time_spam', 'time_valid');
        }
        if (document.querySelector('input[name="test_js"]:checked')) {
            selectedTests.push('js_spam', 'js_valid');
        }
        if (document.querySelector('input[name="test_content"]:checked')) {
            selectedTests.push(
                'content_spam_domain',
                'content_bot_phrase',
                'content_spam_pattern',
                'content_suspicious_email',
                'content_too_many_links',
                'content_valid'
            );
        }

        if (selectedTests.length === 0) {
            alert(decurseTests.i18n.noTestsSelected);
            return;
        }

        // Reset UI
        runButton.disabled = true;
        runButton.innerHTML = '<span class="dashicons dashicons-update spin"></span> ' + decurseTests.i18n.running;
        resultsContainer.style.display = 'block';
        testsList.innerHTML = '';
        summaryContainer.style.display = 'none';
        progressFill.style.width = '0%';
        progressText.textContent = '0%';

        // Run tests sequentially
        var totalTests = selectedTests.length;
        var completedTests = 0;
        var passedTests = 0;
        var failedTests = 0;
        var skippedTests = 0;

        function runNextTest(index) {
            if (index >= selectedTests.length) {
                // All tests complete
                showSummary(passedTests, failedTests, skippedTests, totalTests);
                runButton.disabled = false;
                runButton.innerHTML = '<span class="dashicons dashicons-controls-play"></span> ' + decurseTests.i18n.runTests;
                return;
            }

            var testType = selectedTests[index];

            // Add pending item
            var testItem = document.createElement('div');
            testItem.className = 'test-item test-running';
            testItem.id = 'test-' + testType;
            testItem.innerHTML = '<span class="test-icon"><span class="dashicons dashicons-update spin"></span></span>' +
                '<span class="test-name">' + decurseTests.i18n.runningTest + '</span>' +
                '<span class="test-details"></span>';
            testsList.appendChild(testItem);

            // Scroll to bottom
            testsList.scrollTop = testsList.scrollHeight;

            // Run AJAX request
            var xhr = new XMLHttpRequest();
            xhr.open('POST', decurseTests.ajaxUrl, true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    completedTests++;
                    var progress = Math.round((completedTests / totalTests) * 100);
                    progressFill.style.width = progress + '%';
                    progressText.textContent = progress + '%';

                    if (xhr.status === 200) {
                        try {
                            var response = JSON.parse(xhr.responseText);
                            if (response.success) {
                                updateTestItem(testItem, response.data);

                                if (response.data.result === 'skipped') {
                                    skippedTests++;
                                } else if (response.data.result === response.data.expected) {
                                    passedTests++;
                                } else {
                                    failedTests++;
                                }
                            } else {
                                updateTestItemError(testItem, response.data || 'Error');
                                failedTests++;
                            }
                        } catch (e) {
                            updateTestItemError(testItem, 'Parse error');
                            failedTests++;
                        }
                    } else {
                        updateTestItemError(testItem, 'HTTP ' + xhr.status);
                        failedTests++;
                    }

                    // Small delay for visual effect
                    setTimeout(function() {
                        runNextTest(index + 1);
                    }, 150);
                }
            };

            xhr.send(
                'action=decurse_run_tests' +
                '&test_type=' + encodeURIComponent(testType) +
                '&nonce=' + encodeURIComponent(decurseTests.nonce)
            );
        }

        // Start running tests
        runNextTest(0);
    }

    function updateTestItem(item, data) {
        var iconClass, statusClass;

        if (data.result === 'skipped') {
            iconClass = 'dashicons-minus';
            statusClass = 'test-skipped';
        } else if (data.result === data.expected) {
            iconClass = 'dashicons-yes-alt';
            statusClass = 'test-passed';
        } else {
            iconClass = 'dashicons-dismiss';
            statusClass = 'test-failed';
        }

        item.className = 'test-item ' + statusClass;
        item.innerHTML = '<span class="test-icon"><span class="dashicons ' + iconClass + '"></span></span>' +
            '<span class="test-name">' + escapeHtml(data.name) + '</span>' +
            '<span class="test-details">' + escapeHtml(data.details) + '</span>';
    }

    function updateTestItemError(item, error) {
        item.className = 'test-item test-failed';
        item.innerHTML = '<span class="test-icon"><span class="dashicons dashicons-dismiss"></span></span>' +
            '<span class="test-name">Error</span>' +
            '<span class="test-details">' + escapeHtml(error) + '</span>';
    }

    function showSummary(passed, failed, skipped, total) {
        var summaryContainer = document.getElementById('decurse-tests-summary');
        var statusClass = failed > 0 ? 'summary-failed' : 'summary-passed';

        var html = '<div class="summary-content ' + statusClass + '">';

        if (failed === 0) {
            html += '<span class="dashicons dashicons-yes-alt"></span>';
            html += '<strong>' + decurseTests.i18n.allPassed + '</strong>';
        } else {
            html += '<span class="dashicons dashicons-warning"></span>';
            html += '<strong>' + decurseTests.i18n.someFailures + '</strong>';
        }

        html += '<div class="summary-stats">';
        html += '<span class="stat-passed">' + passed + ' ' + decurseTests.i18n.passed + '</span>';
        if (failed > 0) {
            html += '<span class="stat-failed">' + failed + ' ' + decurseTests.i18n.failed + '</span>';
        }
        if (skipped > 0) {
            html += '<span class="stat-skipped">' + skipped + ' ' + decurseTests.i18n.skipped + '</span>';
        }
        html += '</div>';
        html += '</div>';

        summaryContainer.innerHTML = html;
        summaryContainer.style.display = 'block';
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
})();
