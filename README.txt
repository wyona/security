

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
