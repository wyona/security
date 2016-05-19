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

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * The user history is a list of history entries.
 */
public class UserHistory {

    public class HistoryEntry {
        /**
         * The date the entry took place
         */
        private Date date;

        /**
         * The usecase / action, e.g. 'login'
         */
        private String usecase;

        /**
         * The description of the history entry, e.g. 'authentication failed'
         */
        private String description;

        /**
         * Constructor using all fields
         * 
         * @param date
         * @param usecase
         * @param description
         */
        public HistoryEntry(Date date, String usecase, String description) {
            this.date = date;
            this.usecase = usecase;
            this.description = description;
        }

        /**
         *
         */
        public String getDescription() {
            return description;
        }

        /**
         *
         */
        public String getUsecase() {
            return usecase;
        }

        /**
         *
         */
        public Date getDate() {
            return date;
        }

        /**
         * Get a string representation for this entry
         */
        public String toString() {
            StringBuffer sb = new StringBuffer();
            sb.append(this.date.toString());
            sb.append(" - ");
            sb.append(this.usecase);
            sb.append(" - ");
            sb.append(this.description);
            return sb.toString();
        }
    }

    /**
     * The history list
     */
    private List history;

    /**
     * Add a history entry
     * 
     * @param entry
     */
    public void addEntry(HistoryEntry entry) {
        if (this.history == null) {
            this.history = new ArrayList();
        }
        this.history.add(entry);
    }

    /**
     * Returns the history
     * 
     * @return the history
     */
    public List getHistory() {
        return history;
    }

    /**
     * Returns a string representation of the history with each element separated by newline
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        for (Iterator iterator = this.history.iterator(); iterator.hasNext();) {
            sb.append(iterator.next());
            sb.append("\n");
        }
        return sb.toString();
    }

}
