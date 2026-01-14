/**
 * Decurse Antispam - Uninstall confirmation dialog
 *
 * Shows a modal when DEACTIVATING the plugin (not deleting), because once deactivated
 * the plugin files are no longer loaded. The preference is saved before deactivation.
 */
(function() {
    'use strict';

    // Check if localization is available
    if (typeof decurseUninstall === 'undefined') {
        return;
    }

    // Wait for DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        initUninstallDialog();
    });

    function initUninstallDialog() {
        // Find the deactivate link for our plugin (while plugin is still active)
        var pluginRow = document.querySelector('tr[data-slug="decurse-antispam"]');

        if (!pluginRow) {
            pluginRow = document.querySelector('tr[data-plugin="decurse-antispam/decurse-antispam.php"]');
        }

        if (!pluginRow) {
            return;
        }

        // Find deactivate link (not delete - plugin must be active for our script to run)
        var deactivateLink = pluginRow.querySelector('span.deactivate a');

        if (!deactivateLink) {
            deactivateLink = pluginRow.querySelector('.deactivate a');
        }

        if (!deactivateLink) {
            deactivateLink = pluginRow.querySelector('a[href*="action=deactivate"]');
        }

        if (!deactivateLink) {
            return;
        }

        // Create modal
        var modal = createModal();
        document.body.appendChild(modal);

        // Intercept deactivate click
        deactivateLink.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();

            var originalHref = this.href;
            showModal(modal, originalHref);
        });
    }

    function createModal() {
        var modal = document.createElement('div');
        modal.id = 'decurse-uninstall-modal';
        modal.className = 'decurse-uninstall-modal';
        modal.innerHTML =
            '<div class="decurse-uninstall-modal-content">' +
                '<div class="decurse-uninstall-modal-header">' +
                    '<h2>' + decurseUninstall.i18n.title + '</h2>' +
                '</div>' +
                '<div class="decurse-uninstall-modal-body">' +
                    '<p>' + decurseUninstall.i18n.message + '</p>' +
                    '<div class="decurse-uninstall-options">' +
                        '<label class="decurse-uninstall-option">' +
                            '<input type="radio" name="decurse_delete_data" value="0" checked>' +
                            '<span class="option-content">' +
                                '<strong>' + decurseUninstall.i18n.keepData + '</strong>' +
                                '<small>' + decurseUninstall.i18n.keepDataDesc + '</small>' +
                            '</span>' +
                        '</label>' +
                        '<label class="decurse-uninstall-option decurse-uninstall-option-danger">' +
                            '<input type="radio" name="decurse_delete_data" value="1">' +
                            '<span class="option-content">' +
                                '<strong>' + decurseUninstall.i18n.deleteData + '</strong>' +
                                '<small>' + decurseUninstall.i18n.deleteDataDesc + '</small>' +
                            '</span>' +
                        '</label>' +
                    '</div>' +
                '</div>' +
                '<div class="decurse-uninstall-modal-footer">' +
                    '<button type="button" class="button decurse-uninstall-cancel">' +
                        decurseUninstall.i18n.cancel +
                    '</button>' +
                    '<button type="button" class="button button-primary decurse-uninstall-confirm">' +
                        decurseUninstall.i18n.confirm +
                    '</button>' +
                '</div>' +
            '</div>';

        return modal;
    }

    function showModal(modal, deleteUrl) {
        modal.style.display = 'flex';

        var cancelBtn = modal.querySelector('.decurse-uninstall-cancel');
        var confirmBtn = modal.querySelector('.decurse-uninstall-confirm');

        // Remove old event listeners by cloning
        var newCancelBtn = cancelBtn.cloneNode(true);
        var newConfirmBtn = confirmBtn.cloneNode(true);
        cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        // Cancel button
        newCancelBtn.addEventListener('click', function() {
            hideModal(modal);
        });

        // Confirm button
        newConfirmBtn.addEventListener('click', function() {
            var deleteData = modal.querySelector('input[name="decurse_delete_data"]:checked').value;

            // Save preference via AJAX, then proceed with deletion
            savePreferenceAndDelete(deleteData, deleteUrl, modal);
        });

        // Close on backdrop click
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                hideModal(modal);
            }
        });

        // Close on Escape
        document.addEventListener('keydown', function escHandler(e) {
            if (e.key === 'Escape') {
                hideModal(modal);
                document.removeEventListener('keydown', escHandler);
            }
        });
    }

    function hideModal(modal) {
        modal.style.display = 'none';
    }

    function savePreferenceAndDelete(deleteData, deleteUrl, modal) {
        var confirmBtn = modal.querySelector('.decurse-uninstall-confirm');
        confirmBtn.disabled = true;
        confirmBtn.textContent = decurseUninstall.i18n.processing;

        // Send AJAX request to save preference
        var xhr = new XMLHttpRequest();
        xhr.open('POST', decurseUninstall.ajaxUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                // Regardless of response, proceed with deletion
                window.location.href = deleteUrl;
            }
        };

        xhr.send(
            'action=decurse_save_delete_preference' +
            '&delete_data=' + encodeURIComponent(deleteData) +
            '&nonce=' + encodeURIComponent(decurseUninstall.nonce)
        );
    }
})();
