/*
 * Copyright 2007 Wyona
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.wyona.org/licenses/APACHE-LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wyona.security.core;

import org.apache.log4j.Category;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.yarep.core.Repository;

/**
 * 
 */
public abstract class PolicyManagerFactory {

    private static Category log = Category.getInstance(PolicyManagerFactory.class);

    /**
     * Obtain a new instance of a PolicyManagerFactory. This method uses the
     * following ordered lookup procedure to determine the MapFactory
     * implementation class to load: - Use the
     * org.wyona.security.core.PolicyManagerFactory system property. - Use the
     * properties file "security.properties" in the classpath. This
     * configuration file is in standard java.util.Properties format and
     * contains the fully qualified name of the implementation class with the
     * key being the system property defined above. - Use the Services API (as
     * detailed in the JAR specification), if available, to determine the
     * classname. The Services API will look for a classname in the file
     * META-INF/services/org.wyona.security.core.PolicyManagerFactory in jars
     * available to the runtime.
     * 
     * Once an application has obtained a reference to a PolicyManagerFactory it
     * can use the factory to configure and obtain maps instances.
     */
    public static PolicyManagerFactory newInstance() {
        // TODO: See for implementation
        // http://java.sun.com/j2se/1.4.2/docs/api/javax/xml/parsers/SAXParserFactory.html#newInstance()
        try {
            return (PolicyManagerFactory) Class.forName(
                    "org.wyona.security.impl.PolicyManagerFactoryImpl").newInstance();
        } catch (Exception e) {
            log.error(e);
        }
        return null;
    }

    /**
     * Create a new PolicyManager backed by a yarep repository
     * 
     * @param policiesRepository
     *            The yarep repository to use
     * @return Returns a new PolicyManager implementation
     */
    public abstract PolicyManager newPolicyManager(Repository policiesRepository);

    /**
     * Create a new PolicyManager with a custom configuration.
     * 
     * <p>
     * Allows for custom configuration like this:
     * </p>
     * 
     * <pre>
     * &lt;ac-policies class=&quot;bar.foo.PolicyManagerImpl&quot;&gt;
     *   &lt;foo:database xmlns:foo=&quot;http://foo.bar/&quot;&gt;jdbc://foo.bar:xxx&lt;/foo:database&gt; 
     * &lt;/ac-policies&gt;
     * </pre>
     * 
     * <p>
     * Example: A Yanel realm will parse the custom configuration into a DOM Document and
     * wrap it into an element called "policy-manager-config" in the namespace
     * "http://www.wyona.org/security/1.0".
     * </p>
     * 
     * @param configuration
     *            The custom configuration as DOM Document
     * @return Returns a new PolicyManager implementation
     */
    public abstract PolicyManager newPolicyManager(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver);
}
