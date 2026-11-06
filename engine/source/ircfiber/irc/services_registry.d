module ircfiber.irc.services_registry;

import ircfiber.irc.services_grammar : preloadAnopeCatalogs;
import ircfiber.irc.services_channel : registerChannelServicesOperations;
import ircfiber.irc.services_identity : registerIdentityServicesOperations;
import ircfiber.irc.services_staff : registerStaffServicesOperations;

/// Install the actual-user command adapters before connections are loaded.
void initializeServicesOperations() {
    preloadAnopeCatalogs();
    registerChannelServicesOperations();
    registerIdentityServicesOperations();
    registerStaffServicesOperations();
}
