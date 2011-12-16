

    README
    ======

    Running the tests:
    ------------------

     Run all the tests by executing "ant test" or rather

     "./build.sh test"

     Run a particular test class:

     ./build.sh test -Dtest.class.name=org.wyona.security.test.YarepGroupImplTest
         tail -F build/log/TEST-org.wyona.security.test.YarepGroupImplTest.xml
         ls build/repository/repository2/content/users/

     ./build.sh test -Dtest.class.name=org.wyona.security.test.LDAPIdentityManagerImplTest
     ./build.sh test -Dtest.class.name=org.wyona.security.test.IdentityManagerImplTest


     Creating a release
     ------------------

     1) Update revision number (subversion.revision) within build.properties
     2) Set credentials (username and password) within local.build.properties
     3) Run ./build.sh git-clone
     4) Change directory: build/git-clone-master-rREVISION
     4.1) Update build.properties (revision number) and local.build.properties (credentials) accordingly
     5) Run ./build.sh deploy-jars
