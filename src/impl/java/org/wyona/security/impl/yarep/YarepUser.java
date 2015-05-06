package org.wyona.security.impl.yarep;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfiguration;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.wyona.security.core.ExpiredIdentityException;
import org.wyona.security.core.UserHistory;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.UserManager;
import org.wyona.security.core.api.User;
import org.wyona.security.impl.Password;

import org.wyona.yarep.core.Node;

import org.wyona.commons.xml.XMLHelper;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * User implementation based on Yarep
 */
public class YarepUser extends YarepItem implements User {

    private static Logger log = LogManager.getLogger(YarepUser.class);

    public static final String USER = "user";

    public static final String ALIASES_TAG_NAME = "aliases";
    public static final String ALIAS_TAG_NAME = "alias";
    public static final String ALIAS_ID_ATTR_NAME = "id";

    public static final String GROUPS_TAG_NAME = "groups";
    public static final String GROUP_TAG_NAME = "group";
    public static final String GROUP_ID_ATTR_NAME = "id";

    public static final String EMAIL = "email";

    public static final String LANGUAGE = "language";

    public static final String PASSWORD = "password";

    public static final String SALT = "salt";

    public static final String ALGORITHM_ATTR_NAME = "algorithm";

    public static final String EXPIRE = "expire";

    private static final String DATE_ATTR = "date";
    private static final String USECASE_ATTR = "usecase";
    private static final String DESCRIPTION_ATTR = "description";
    private static final String EVENT_TAG_NAME = "event";

    public static final String DESCRIPTION = "description";

    private static final String HISTORIES_BASE_NODE_NAME = "histories";
    private static final String HISTORY_XML_DOC_NODE_NAME = "history.xml";

    /**
     * Date format used for the expired value
     */
    public static final String DATE_FORMAT = "yyyy-MM-dd";
    public static final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    private String email;

    private String language;

    private String hashedPassword;
    private String hashingAlgorithm;

    private String salt;

    private String description;

    private Date expire;

    private ArrayList<String> _groupIDs;
    private ArrayList<String> aliasIDs;

    private boolean upgraded = false;

    /**
     * Instantiates an existing YarepUser from a repository node.
     *
     * @param userManager
     * @param groupManager
     * @param node Yarep node containing user information, e.g. hashed password
     */
    public YarepUser(UserManager userManager, GroupManager groupManager, Node node) throws AccessManagementException {
        // INFO: This will call configure()
        super(userManager, groupManager, node);

        // Check if we need to upgrade the password hash
        if(hashingAlgorithm != null && !hashingAlgorithm.startsWith("bcrypt")) {
            upgradeDoubleHash(this.hashedPassword, this.hashingAlgorithm);
        }
    }

    /**
     * Creates a new YarepUser with a given id and name (not persistent)
     *
     * @param userManager
     * @param groupManager
     * @param id
     * @param name
     */
    public YarepUser(UserManager userManager, GroupManager groupManager, String id, String name) {
        super(userManager, groupManager, id, name);
    }

    /**
     * @see org.wyona.security.impl.yarep.YarepItem#configure(org.apache.avalon.framework.configuration.Configuration)
     */
    protected void configure(Configuration config) throws ConfigurationException, AccessManagementException {
        // Compulsory fields
        setID(config.getAttribute(ID));
        //log.debug("Read user profile: " + getID());

        setName(config.getChild(NAME, false).getValue(null));

        // Optional fields
        if(config.getChild(EMAIL, false) != null){
            setEmail(config.getChild(EMAIL, false).getValue(null));
        }

        if(config.getChild(PASSWORD, false) != null){
            // Do not use setter here because it does other things
            this.hashedPassword = config.getChild(PASSWORD, false).getValue(null);
            if (hashedPassword != null) {
                this.hashingAlgorithm = config.getChild(PASSWORD, false).getAttribute(ALGORITHM_ATTR_NAME, "MD5");
            }
        }

        if(config.getChild(LANGUAGE, false) != null) {
            setLanguage(config.getChild(LANGUAGE, false).getValue(null));
        }

        if(config.getChild(SALT,false) != null) {
            this.salt = config.getChild(SALT, false).getValue(null);
        }

        if(config.getChild(DESCRIPTION, false) != null) {
            setDescription(config.getChild(DESCRIPTION, false).getValue(null));
        }

        if(config.getChild(EXPIRE, false) != null){
            SimpleDateFormat sdf1 = new SimpleDateFormat(DATE_TIME_FORMAT);
            SimpleDateFormat sdf2 = new SimpleDateFormat(DATE_FORMAT);
                String dateAsString = config.getChild(EXPIRE, false).getValue(null);
                Date expire = null;

                if(null != dateAsString){
                    try {
                        expire = sdf2.parse(dateAsString);
                    } catch (ParseException e) {
                        try {
                            expire = sdf1.parse(dateAsString);
                        } catch (ParseException e1) {
                            log.error(e.getMessage() + " (The user will be made expired)");
                        }finally{
                            if(expire == null){
                                GregorianCalendar cal = new GregorianCalendar();
                                cal.add(Calendar.YEAR, -10);
                                expire = cal.getTime();
                            }else{
                                // parsed correctly
                            }
                        }
                    }finally{
                        this.setExpirationDate(expire);
                    }
                }
        }

        Configuration aliasesNode = config.getChild(ALIASES_TAG_NAME, false);
        if (aliasesNode != null) {
            aliasIDs = new ArrayList<String>();
            Configuration[] aliasNodes = aliasesNode.getChildren(ALIAS_TAG_NAME);
            if (aliasNodes != null && aliasNodes.length > 0) {
                for (int i = 0; i < aliasNodes.length; i++) {
                    aliasIDs.add(aliasNodes[i].getAttribute(ALIAS_ID_ATTR_NAME));
                }
            } else {
                log.debug("User '" + getID() + "' does not seem to have any aliases.");
            }
        } else {
            log.debug("User '" + getID() + "' does not seem to have any aliases.");
        }

        Configuration groupsNode = config.getChild(GROUPS_TAG_NAME, false);
        if (groupsNode != null) {
            _groupIDs = new ArrayList<String>();
            Configuration[] groupNodes = groupsNode.getChildren(GROUP_TAG_NAME);
            if (groupNodes != null && groupNodes.length > 0) {
                for (int i = 0; i < groupNodes.length; i++) {
                    _groupIDs.add(groupNodes[i].getAttribute(GROUP_ID_ATTR_NAME));
                }
            } else {
                //log.debug("User '" + getID() + "' does not seem to belong to any groups.");
            }
        } else { // INFO: For backwards compatibility reason the group IDs are retrieved from the groups themselves and saved as bi-directional links
            log.warn("User '" + getID() + "' does seem to be an instance of a previous version without '" + GROUPS_TAG_NAME + "' tag and hence will be migrated automatically.");
            //if (fixGroupIndex) {
            if (true) {
                log.warn("Fix group index ...");
                String[] gids = getGroupIDs(false);
                _groupIDs = new ArrayList<String>();
                for (int i = 0; i < gids.length; i++) {
                    _groupIDs.add(gids[i]);
                }
                save();
            }
        }
    }

    /**
     * @see org.wyona.security.impl.yarep.YarepItem#createConfiguration()
     */
    protected Configuration createConfiguration() throws AccessManagementException {
        String NAMESPACE_URI = "http://www.wyona.org/security/1.0";
        String PREFIX = "";
        String BUILDER_LOC = "YarepUser";

        DefaultConfiguration config = new DefaultConfiguration(USER, BUILDER_LOC, NAMESPACE_URI, PREFIX);
        config.setAttribute(ID, getID());

        DefaultConfiguration nameNode = new DefaultConfiguration(NAME, BUILDER_LOC, NAMESPACE_URI, PREFIX);
        nameNode.setValue(getName());
        config.addChild(nameNode);

        if(getEmail() != null){
            DefaultConfiguration emailNode = new DefaultConfiguration(EMAIL, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            emailNode.setValue(getEmail());
            config.addChild(emailNode);
        }

        if(getLanguage() != null){
            DefaultConfiguration languageNode = new DefaultConfiguration(LANGUAGE, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            languageNode.setValue(getLanguage());
            config.addChild(languageNode);
        }

        if(getPassword() != null){
            DefaultConfiguration passwordNode = new DefaultConfiguration(PASSWORD, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            passwordNode.setValue(getPassword());
            if (hashingAlgorithm != null) {
                passwordNode.setAttribute(ALGORITHM_ATTR_NAME, hashingAlgorithm);
            }
            config.addChild(passwordNode);
        }

        if(getDescription() != null){
            DefaultConfiguration descriptionNode = new DefaultConfiguration(DESCRIPTION, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            descriptionNode.setValue(getDescription());
            config.addChild(descriptionNode);
        }

        if(getExpirationDate() != null){
            DefaultConfiguration expireNode = new DefaultConfiguration(EXPIRE, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            expireNode.setValue(new SimpleDateFormat(DATE_TIME_FORMAT).format(getExpirationDate()));
            config.addChild(expireNode);
        }

        if(getSalt() != null) {
            DefaultConfiguration saltNode = new DefaultConfiguration(SALT, BUILDER_LOC, NAMESPACE_URI, PREFIX);
            saltNode.setValue(getSalt());
            config.addChild(saltNode);
        }

        DefaultConfiguration aliasesNode = new DefaultConfiguration(ALIASES_TAG_NAME, BUILDER_LOC, NAMESPACE_URI, PREFIX);
        config.addChild(aliasesNode);
        if (aliasIDs != null && aliasIDs.size() > 0) {
            for (int i = 0; i < aliasIDs.size(); i++) {
                DefaultConfiguration aliasNode = new DefaultConfiguration(ALIAS_TAG_NAME, BUILDER_LOC, NAMESPACE_URI, PREFIX);
                aliasNode.setAttribute(ALIAS_ID_ATTR_NAME, (String) aliasIDs.get(i));
                aliasesNode.addChild(aliasNode);
            }
        } else {
            aliasIDs = new ArrayList<String>();
        }

        DefaultConfiguration groupsNode = new DefaultConfiguration(GROUPS_TAG_NAME, BUILDER_LOC, NAMESPACE_URI, PREFIX);
        config.addChild(groupsNode);
        if (_groupIDs != null && _groupIDs.size() > 0) {
            for (int i = 0; i < _groupIDs.size(); i++) {
                DefaultConfiguration groupNode = new DefaultConfiguration(GROUP_TAG_NAME, BUILDER_LOC, NAMESPACE_URI, PREFIX);
                groupNode.setAttribute(GROUP_ID_ATTR_NAME, (String) _groupIDs.get(i));
                groupsNode.addChild(groupNode);
            }
        } else {
            _groupIDs = new ArrayList<String>();
        }

        return config;
    }

    /**
     * @see org.wyona.security.core.api.User#authenticate(java.lang.String)
     */
    @SuppressWarnings("deprecation")
    public boolean authenticate(String plainTextPassword) throws ExpiredIdentityException, AccessManagementException {
        if(isExpired()){
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT);
            throw new ExpiredIdentityException("Identity expired on " + sdf.format(getExpirationDate()));
        }

        boolean result = false;
        String id = getID();
        String hash = getPassword();
        String salt = getSalt();

        if(hashingAlgorithm == null || hashingAlgorithm.equals("MD5")) {
            // Deprecated MD5 hashing detected.
            log.warn("Detected deprecated hashing algorithm for user: " + id);

            if(salt == null) {
                result = hash.equals(Password.getMD5(plainTextPassword));
            } else {
                result = hash.equals(Password.getMD5(plainTextPassword, salt));
            }

            upgradePlainHash(plainTextPassword);
        } else if(hashingAlgorithm.equals("bcrypt-MD5")) {
            // Bcrypt-hashed md5-hash detected
            log.warn("Detected double hash algorithm for user: " + id);

            String md5;
            if(salt == null) {
                md5 = Password.getMD5(plainTextPassword);
            } else {
                md5 = Password.getMD5(plainTextPassword, salt);
            }
            result = Password.verifyBCrypt(md5, hash);

            upgradePlainHash(plainTextPassword);
        } else if(hashingAlgorithm.equals("SHA-256")) {
            // Deprecated SHA-256 hashing detected.
            log.warn("Detected deprecated hashing algorithm for user: " + id);

            if(salt == null) salt = "";
            result = hash.equals(Password.getSHA256(plainTextPassword, salt));

            upgradePlainHash(plainTextPassword);
        } else if(hashingAlgorithm.equals("bcrypt-SHA-256")) {
            // Bcrypt-hashed sha256-hash detected
            log.warn("Detected double hash algorithm for user: " + id);

            if(salt == null) salt = "";
            String sha256 = Password.getSHA256(plainTextPassword, salt);
            result = Password.verifyBCrypt(sha256, hash);

            upgradePlainHash(plainTextPassword);
        } else if(hashingAlgorithm.equals("bcrypt")) {
            // Proper bcrypt hashing detected :-)
            result = Password.verifyBCrypt(plainTextPassword, hash);
        } else {
            // Unkown hashing algorithm, abort.
            log.error("No such hashing algorithm known: " + hashingAlgorithm);
            result = false;
        }

        UserHistory history = getHistory();
        if (history == null) {
            history = new UserHistory();
        }
        if (result) {
            history.addEntry(new org.wyona.security.core.UserHistory().new HistoryEntry(new Date(), "login", "successful"));
        } else {
            history.addEntry(new org.wyona.security.core.UserHistory().new HistoryEntry(new Date(), "login", "failed"));
        }
        setHistory(history);

        return result;
    }

    /**
     * Upgrade a deprecated hash with the plain-text password.
     * Note: This only takes effect after the user is actually stored back
     * to disk again. However, this way we can make sure that any modification
     * to the user also automatically causes the hash to be upgraded.
     */
    private void upgradePlainHash(String plainTextPassword) {
        this.hashingAlgorithm = "bcrypt";
        this.hashedPassword = Password.getBCrypt(plainTextPassword);
        this.upgraded = true;
        // BCrypt doesn't need the salt field, so we clear it.
        this.salt = "";
    }

    /**
     * Upgrade a deprecated hash by re-hashing an old hash.
     * Note: This only takes effect after the user is actually stored back
     * to disk again. However, this way we can make sure that any modification
     * to the user also automatically causes the hash to be upgraded.
     */
    private void upgradeDoubleHash(String hashedPassword, String oldAlgorithm) {
        this.hashingAlgorithm = "bcrypt-" + oldAlgorithm;
        this.hashedPassword = Password.getBCrypt(hashedPassword);
        this.upgraded = true;
    }

    /**
     * Check if user has been (in some way) upgraded.
     */
    public boolean isUpgraded() {
        return upgraded;
    }

    /**
     * @deprecated Use org.wyona.security.impl.util.UserUtil#isExpired(User) instead
     */
    protected boolean isExpired() {
        return org.wyona.security.impl.util.UserUtil.isExpired(this);
    }

    /**
     * @see org.wyona.security.core.api.User#getDescription()
     */
    public String getDescription() {
        return description;
    }

    /**
     * @see org.wyona.security.core.api.User#getEmail()
     */
    public String getEmail() throws AccessManagementException {
        return this.email;
    }

    /**
     * @see org.wyona.security.core.api.User#getLanguage()
     */
    public String getLanguage() throws AccessManagementException {
        return this.language;
    }

    /**
     * @see org.wyona.security.core.api.User#getSalt()
     */
    public String getSalt() throws AccessManagementException {
        return this.salt;
    }

    /**
     * @see org.wyona.security.core.api.User#getGroups()
     */
    public Group[] getGroups() throws AccessManagementException {
        if(log.isDebugEnabled()) log.debug("Get groups for user: " + getID() + ", " + getName());
        ArrayList<Group> groups = new ArrayList<Group>();
        if (getGroupManager() != null) {
            String[] groupIDs = getGroupIDs(false);
            if (groupIDs != null) {
                for (int i = 0; i < groupIDs.length; i++) {
                    Group group = getGroupManager().getGroup(groupIDs[i]);
                    if (group != null) {
                        groups.add(group);
                    } else {
                        log.warn("User '" + getID() + "' seems to be member of group '" + groupIDs[i] + "', but no such group exists!");
                    }
                }
            } else {
                log.warn("User '" + getID() + "' does not seem to belong to any groups.");
            }
        }
        return (Group[]) groups.toArray(new Group[groups.size()]);
    }

    /**
     * @see org.wyona.security.core.api.User#getGroups(boolean)
     */
    public Group[] getGroups(boolean parents) throws AccessManagementException {
        if (parents) {
            log.info("Resolve parent groups for user '" + getID() + "' ...");
            String[] groupIDs = getGroupIDs(false);

            Vector<String> branchGroups = new Vector<String>();
            Vector<Group> groupsInclSubGroups = new Vector<Group>();
            for (int i = 0; i < groupIDs.length; i++) {
                try {
                    groupsInclSubGroups.add(getGroupManager().getGroup(groupIDs[i]));
                    branchGroups.add(groupIDs[i]);
                    getParentGroups(groupIDs[i], branchGroups, groupsInclSubGroups);
                    branchGroups.remove(groupIDs[i]);
                } catch (Exception e) {
                    log.error(e, e);
                    throw new AccessManagementException(e);
                }
            }
            log.debug("Get parent groups including parents of parents: " + groupsInclSubGroups.size());
            return (Group[])groupsInclSubGroups.toArray(new Group[groupsInclSubGroups.size()]);
        } else {
            log.debug("Get parent groups excluding parents of parents: " + getGroups().length);
            return getGroups();
        }
    }

    /**
     * @see org.wyona.security.core.api.User#getGroupIDs(boolean)
     */
    public String[] getGroupIDs(boolean parents) throws AccessManagementException {
        YarepGroupManager ygm = (YarepGroupManager) getGroupManager();
        if (ygm != null) {
            ArrayList<String> groupIDs = new ArrayList<String>();

            if (_groupIDs != null) {
                for (int i = 0; i < _groupIDs.size(); i++) {
                    groupIDs.add((String) _groupIDs.get(i));
                }
            } else {
                log.warn("Use deprecated implementation ...");
                Node[] groupNodes = ygm.getAllGroupNodes();
                for (int i = 0; i < groupNodes.length; i++) {
                    if (YarepGroup.isUserMember(groupNodes[i], getID())) {
                        try {
                            String groupID = YarepGroup.getGroupID(groupNodes[i]);
                            log.debug("User '" + getID() + "' is user member of group: " + groupID);
                            groupIDs.add(groupID);
                        } catch(Exception e) {
                            log.error(e, e);
                        }
                    }
                }
            }

            if (parents) {
                log.info("Resolve parent groups for user '" + getID() + "' ...");

                ArrayList<String> groupIDsInclParents = new ArrayList<String>();
                ArrayList<String> branchGroups = new ArrayList<String>();
                for (int i = 0; i < groupIDs.size(); i++) {
                    try {
                        // TOOD: Replace this implementation
                        groupIDsInclParents.add((String) groupIDs.get(i));
                        branchGroups.add((String) groupIDs.get(i)); // INFO: Add in order to detect loops with a particular branch
                        getParentGroupIDsImplV2((String) groupIDs.get(i), branchGroups, groupIDsInclParents);
                        branchGroups.remove((String) groupIDs.get(i)); // INFO: Remove in order to avoid "phantom" loops with regard to multiple branches
                    } catch(Exception e) {
                        log.error(e, e);
                    }
                }
                log.debug("Get parent group IDs of user '" + getID() + "' including parents of parents: " + groupIDsInclParents.size());
                return (String[]) groupIDsInclParents.toArray(new String[groupIDsInclParents.size()]);
            } else {
                log.debug("Get parent group IDs of user '" + getID() + "' excluding parents of parents: " + groupIDs.size());
                return (String[]) groupIDs.toArray(new String[groupIDs.size()]);
            }
        } else {
            log.error("Group manager is null!");
            return null;
        }
    }

    /**
     * Get parent groups of a particular group
     * @param groupID ID of particular group for which parent groups shall be found
     * @param branchGroups Groups which have already been found within this branch
     * @param groupsInclSubGroups Groups which have already been found
     */
    private void getParentGroups(String groupID, Vector<String> branchGroups, Vector<Group> groupsInclSubGroups) throws Exception {
        Group[] parentGroups = getGroupManager().getGroup(groupID).getParents();
        if (parentGroups != null && parentGroups.length > 0) {
            if (log.isDebugEnabled()) log.debug("Parent groups found of group '" + groupID + "'");
            for (int i = 0; i < parentGroups.length; i++) {
                if (log.isDebugEnabled()) log.debug("Check if parent group '" + parentGroups[i].getID() + "' is already contained ...");

                boolean alreadyContainedWithinBranch = false;
                for (int k = 0; k < branchGroups.size(); k++) {
                    if (parentGroups[i].getID().equals((String)branchGroups.elementAt(k))) {
                        log.warn("Maybe loop detected for group '" + groupID + "' and parent group '" + parentGroups[i].getID() + "', but maybe only root group '" + parentGroups[i].getID() + "' reached!");
                        alreadyContainedWithinBranch = true;
                        break;
                    }
                }

                if (!alreadyContainedWithinBranch) {
                    if (log.isDebugEnabled()) log.debug("Add parent group '" + parentGroups[i].getID() + "'!");

                    boolean alreadyPartOfList = false;
                    for (int k = 0; k < groupsInclSubGroups.size(); k++) {
                        if (parentGroups[i].getID().equals(((Group)groupsInclSubGroups.elementAt(k)).getID())) {
                            alreadyPartOfList = true;
                            break;
                        }
                    }
                    if (!alreadyPartOfList) {
                        groupsInclSubGroups.add(parentGroups[i]);
                    }

                    branchGroups.add(parentGroups[i].getID());
                    getParentGroups(parentGroups[i].getID(), branchGroups, groupsInclSubGroups);
                    branchGroups.remove(parentGroups[i].getID());
                }
            }
        } else {
            if (log.isDebugEnabled()) log.debug("Group '" + groupID + "' does not seem to have parent groups.");
        }
    }

    /**
     * @see org.wyona.security.core.api.User#setEmail(java.lang.String)
     */
    public void setEmail(String email) throws AccessManagementException {
        this.email = email;
    }

    /**
     * @see org.wyona.security.core.api.User#setLanguage(java.lang.String)
     */
    public void setLanguage(String language) throws AccessManagementException {
        this.language = language;
    }

    /**
     * @see org.wyona.security.core.api.User#unsetLanguage()
     */
    public void unsetLanguage() throws AccessManagementException {
        this.language = null;
    }

    /**
     * @see org.wyona.security.core.api.User#setPassword(java.lang.String)
     */
    public void setPassword(String plainTextPassword) throws AccessManagementException {
        this.hashedPassword = Password.getBCrypt(plainTextPassword);
        this.hashingAlgorithm = "bcrypt";
    }

    /**
     * @see org.wyona.security.core.api.User#setSalt()
     * @deprecated Salting is now done using bcrypt, which has it built-in.
     */
    public void setSalt() throws AccessManagementException {
        // Deprecated: Salting is now directly built into the hashing
        // algorithm and does not need to be handled separately. The function
        // still needs to be around to satisfy the API however.
        this.salt = "";
    }

    /**
     * @see org.wyona.security.core.api.User#setDescription(java.lang.String)
     */
    public void setDescription(String description) throws AccessManagementException {
        this.description = description;
    }

    /**
     * Gets the password hash
     * @return encrypted password
     * @throws AccessManagementException
     */
    protected String getPassword() throws AccessManagementException {
        return this.hashedPassword;
    }

    /**
     * @see org.wyona.security.core.api.User#getExpirationDate()
     */
    public Date getExpirationDate() {
        return expire;
    }

    /**
     * @see org.wyona.security.core.api.User#setExpirationDate(Date)
     */
    public void setExpirationDate(Date date) {
        this.expire = date;
    }

    /**
     * @see org.wyona.security.core.api.User#getHistory()
     */
    public UserHistory getHistory() {
        try {
            Node historyNode = getHistoryNode();
            log.warn("DEBUG: History node: " + historyNode.getPath());

            Document doc = null;
            Node xmlDocNode = null;
            if (historyNode.hasNode(HISTORY_XML_DOC_NODE_NAME)) {
                xmlDocNode = historyNode.getNode(HISTORY_XML_DOC_NODE_NAME);
                doc = XMLHelper.readDocument(xmlDocNode.getInputStream());
                UserHistory history = new UserHistory();
                Element[] entryEls = XMLHelper.getChildElements(doc.getDocumentElement(), EVENT_TAG_NAME, null);
                for (int i = 0; i < entryEls.length; i++) {
                    Date date = new Date(new Long(entryEls[i].getAttribute(DATE_ATTR)).longValue());
                    String usecase = entryEls[i].getAttribute(USECASE_ATTR);
                    String desc = entryEls[i].getAttribute(DESCRIPTION_ATTR);
                    history.addEntry(new org.wyona.security.core.UserHistory().new HistoryEntry(date, usecase, desc));
                }
                return history;
            } else {
                return null;
            }
        } catch(Exception e) {
            log.error(e, e);
            return null;
        }
    }

    /**
     * @see org.wyona.security.core.api.User#setHistory(UserHistory)
     */
    public void setHistory(UserHistory history) {
        if (history != null) {
            java.util.List<org.wyona.security.core.UserHistory.HistoryEntry> entries = history.getHistory();
            try {
                Node historyNode = getHistoryNode();
                log.warn("DEBUG: History node: " + historyNode.getPath());

                int DEFAULT_SIZE = 3;
                int maxSize = DEFAULT_SIZE;
                Node xmlDocNode = null;
                if (historyNode.hasNode(HISTORY_XML_DOC_NODE_NAME)) {
                    xmlDocNode = historyNode.getNode(HISTORY_XML_DOC_NODE_NAME);
                    maxSize = new Integer(XMLHelper.readDocument(xmlDocNode.getInputStream()).getDocumentElement().getAttribute("max-size")).intValue();
                } else {
                    xmlDocNode = historyNode.addNode(HISTORY_XML_DOC_NODE_NAME, org.wyona.yarep.core.NodeType.RESOURCE);
                }
                Document doc = XMLHelper.createDocument("http://www.wyona.org/security/user/history/1.0.0", "user-history");
                Element rootEl = doc.getDocumentElement();
                rootEl.setAttribute("max-size", "" + maxSize);

                int counter = 0;
                for (org.wyona.security.core.UserHistory.HistoryEntry entry: entries) {
                    counter++;
                    if (entries.size() - counter < maxSize) {
                        log.warn("DEBUG: Save history entry: " + entry);
                        Element entryEl = (Element) rootEl.appendChild(doc.createElement(EVENT_TAG_NAME));
                        entryEl.setAttribute(DATE_ATTR, "" + entry.getDate().getTime());
                        entryEl.setAttribute(USECASE_ATTR, entry.getUsecase());
                        entryEl.setAttribute(DESCRIPTION_ATTR, entry.getDescription());
                    } else {
                        log.warn("DEBUG: Drop history entry: " + entry);
                    }
                }

                java.io.OutputStream out = xmlDocNode.getOutputStream();
                XMLHelper.writeDocument(doc, out);
                out.close();
            } catch(Exception e) {
                log.error(e, e);
            }
        } else {
            log.error("History argument is null!");
        }
    }

    /**
     * Get history node of this particular user, e.g. '/histories/1412880733771'
     */
    private Node getHistoryNode() throws Exception {
        Node userNode = getNode();
        Node usersNode = userNode.getParent();
        Node rootNode = usersNode.getParent();

        Node historiesNode = null;
        if (rootNode.hasNode(HISTORIES_BASE_NODE_NAME)) {
            historiesNode = rootNode.getNode(HISTORIES_BASE_NODE_NAME);
        } else {
            historiesNode = rootNode.addNode(HISTORIES_BASE_NODE_NAME, org.wyona.yarep.core.NodeType.COLLECTION);
        }

        Node historyNode = null;
        String nameWithoutSuffix = org.wyona.commons.io.PathUtil.getNameWithoutSuffix(userNode.getName());
        if (historiesNode.hasNode(nameWithoutSuffix)) {
            historyNode = historiesNode.getNode(nameWithoutSuffix);
        } else {
            historyNode = historiesNode.addNode(nameWithoutSuffix, org.wyona.yarep.core.NodeType.COLLECTION);
        }

        return historyNode;
    }

    /**
     * Two users are equal if they have the same id.
     */
    public boolean equals(Object obj) {
        if (obj instanceof User) {
            String id1;
            try {
                id1 = getID();
                String id2 = ((User)obj).getID();
                return id1.equals(id2);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
        return false;
    }

    /**
     * Get parent group IDs of a particular group
     *
     * @param groupID ID of particular group
     * @param branchGroups Group IDs within a specific branch (in order to detect loops with a particular branch, but also in order to avoid "phantom" loops with regard to multiple branches)
     * @param groupIDsInclParents Group IDs which have already been found
     */
    private void getParentGroupIDsImplV2(String groupID, ArrayList<String> branchGroups, ArrayList<String> groupIDsInclParents) throws Exception {
        log.debug("Get parent group IDs for particular group: " + groupID);

        GroupManager gm = getGroupManager();
        if (gm != null) {
            Group[] parentGroups = gm.getGroup(groupID).getParents();
            if (parentGroups != null) {
                for (int i = 0; i < parentGroups.length; i++) {
                    String parentGroupID = parentGroups[i].getID();
                    log.debug("Group '" + groupID + "' is group member of parent group: " + parentGroupID);

                    boolean alreadyContainedWithinBranch = false;
                    //log.debug("DEBUG: Depth of branch: " + branchGroups.size());
                    for (int k = 0; k < branchGroups.size(); k++) {
                        if (branchGroups.get(k).equals(parentGroupID)) {
                            log.error("Maybe loop detected for group '" + groupID + "' and parent group '" + parentGroupID + "' or root group '" + parentGroupID + "' reached! Group resolving will be aborted in order to avoid loop.");
                            alreadyContainedWithinBranch = true;
                            break;
                        }
                    }

                    if (!alreadyContainedWithinBranch) {

                        boolean alreadyPartOfList = false;
                        for (int k = 0; k < groupIDsInclParents.size(); k++) {
                            if (groupIDsInclParents.get(k).equals(parentGroupID)) {
                                alreadyPartOfList = true;
                                break;
                            }
                        }
                        if (!alreadyPartOfList) {
                            groupIDsInclParents.add(parentGroupID);
                        }

                        branchGroups.add(parentGroupID); // INFO: Add parent group in order to detect loops within this particular branch
                        getParentGroupIDsImplV2(parentGroupID, branchGroups, groupIDsInclParents);
                        branchGroups.remove(parentGroupID); // INFO: Remove parent group in order to avoid "phantom" loops with regard to multiple branches
                    }
                }
            } else {
                log.debug("Group '" + groupID + "' does not seem to have parent groups.");
            }
        } else {
            log.error("Group manager is null!");
        }
    }

    /**
     * Add group (creating a bi-directional link)
     * @param id Group ID
     */
    void addGroup(String id) throws AccessManagementException {
        log.info("Add user '" + getID() + "' to group: " + id);
        if (_groupIDs == null) {
            log.warn("User '" + getID() + "' has groups not initialized yet, hence will be initialized!");
            _groupIDs = new ArrayList<String>();
        }
        if (_groupIDs.indexOf(id) < 0) {
            _groupIDs.add(id);
        } else {
            throw new AccessManagementException("User '" + getID() + "' already belongs to group '" + id + "'!");
        }
        save();
    }

    /**
     * Add alias (creating a bi-directional link)
     * @param id Alias ID
     */
    void addAlias(String id) throws AccessManagementException {
        log.info("Add alias '" + id + "' to user: " + getID());

        if (aliasIDs == null) {
            log.warn("User '" + getID() + "' has aliases not initialized yet, hence will be initialized!");
            aliasIDs = new ArrayList<String>();
        }
        if (aliasIDs.indexOf(id) < 0) {
            aliasIDs.add(id);
        } else {
            throw new AccessManagementException("User '" + getID() + "' already has alias '" + id + "'!");
        }
        save();
    }

    /**
     * Remove group (Remove bi-directional link)
     * @param id Group ID
     */
    void removeGroup(String id) throws AccessManagementException {
        log.info("Remove user '" + getID() + "' from group '" + id + "'.");
        if (_groupIDs != null) {
            if (_groupIDs.indexOf(id) >= 0) {
                _groupIDs.remove(_groupIDs.indexOf(id));
            } else {
                log.error("User '" + getID() + "' does not belong to group '" + id + "' (user and group seem to be inconsistent)!");
            }
        } else {
            log.error("User '" + getID() + "' has no groups! (user and groups seem to be inconsistent)");
        }
        save();
    }

    /**
     * Remove alias (Remove bi-directional link)
     * @param id Alias ID
     */
    void removeAlias(String id) throws AccessManagementException {
        log.info("Remove alias '" + id + "' from user '" + getID() + "'.");
        if (aliasIDs != null) {
            if (aliasIDs.indexOf(id) >= 0) {
                aliasIDs.remove(aliasIDs.indexOf(id));
            } else {
                log.error("User '" + getID() + "' does not have any alias '" + id + "'!");
            }
        } else {
            log.error("User '" + getID() + "' has no aliases!");
        }
        save();
    }

    /**
     * @see org.wyona.security.core.api.User@getAliases()
     */
    public String[] getAliases() {
        if (aliasIDs != null) {
            return (String[]) aliasIDs.toArray(new String[aliasIDs.size()]);
        } else {
            try {
                log.warn("User '" + getID() + "' does not seem to have any aliases yet!");
            } catch(Exception e) {
                log.error(e, e);
            }
            return null;
        }
    }
}
