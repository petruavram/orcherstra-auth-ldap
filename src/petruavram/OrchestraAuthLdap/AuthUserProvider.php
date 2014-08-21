<?php namespace petruavram\OrchestraAuthLdap;

use Illuminate\Config\Repository;
use adLDAP;
use Illuminate\Auth\UserProviderInterface;
use Illuminate\Auth\UserInterface;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

use Illuminate\Hashing\HasherInterface;


/**
 * Class to build array to send to GenericUser
 * This allows the fields in the array to be
 * accessed through the Auth::user() method
 */
class AuthUserProvider implements UserProviderInterface
{
    /**
     * Active Directory Object
     * 
     * @var adLDAP\adLDAP
     */
    protected $ad;
    
    /**
     *
     * @var type string
     */
    protected $model;

    /**
     * The hasher implementation.
     *
     * @var \Illuminate\Hashing\HasherInterface
     */
    protected $hasher;
    
    /**
     * DI in adLDAP object for use throughout
     * 
     * @param adLDAP\adLDAP $conn
     * @param array() $config
     * @param string $model
     *
     * TODO: Exception handling. Throw InvalidArgumentException
     */
    public function __construct(HasherInterface $hasher, adLDAP\adLDAP $conn, $config, $model)
    {
        $this->hasher = $hasher;
        $this->ad = $conn;
        $this->config = $config;
        $this->model = $model;
    }

    /**
     * Retrieve a user by their unique idenetifier.
     *
     * @param  mixed  $identifier
     * @return Illuminate\Auth\GenericUser|null
     */
    public function retrieveByID($identifier)
    {
        // A model 
        return $this->createModel()->newQuery()->find( $identifier );
    }

    /**
     * Retrieve a user by by their unique identifier and "remember me" token.
     *
     * @param  mixed $identifier
     * @param  string $token
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveByToken($identifier, $token)
    {
        return; // this shouldn't be needed as user / password is in ldap
    }

    /**
     * @return void
     */
    public function updateRememberToken(UserInterface $user, $token)
    {
        return; // this shouldn't be needed as user / password is in ldap
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return Illuminate\Auth\GenericUser|null
     *
     */
    public function retrieveByCredentials(array $credentials)
    {
        // get he user credentials form settings
        $userCredentialsID = $this->getUsernameField();
        // Check which ones are usable for this model
        $validUserIdentifierFields = $this->validUsernameFields( $userCredentialsID );

        // A model to work with for retriveing via model auth
        $possibleModel = $this->createModel();

        // If the credential given is 'any' we'll check all auth scenarious based on the settings and use the model 
        // based auth method first
        if ( array_key_exists( 'any', $credentials ) ) {

            // the default has priority
            if ( array_key_exists( 'default', $validUserIdentifierFields ) ) {
                $userCredential = $validUserIdentifierFields['default'];

                // Try the default attribute from the model to retrive the user
                if ( $model = $possibleModel->where( $userCredential, $credentials[ 'any' ] )->newQuery()->first() ) {

                    return $model;

                } else {

                    // Ldap auth and make new model
                    $user = $credentials[ 'any' ];

                    if ( ! isset($user) ) {
                        throw new InvalidArgumentException;
                    }

                    // Get info from LDAP
                    $infoCollection = $this->ad->user()->infoCollection( $user, array('*') );

                    // If the user is found and we have the info
                    if ( $infoCollection ) {
                        $ldapUserInfo = $this->setInfoArray($infoCollection);

                        // retrive user and make new user model
                        return new \petruavram\OrchestraAuthLdap\User((array) $ldapUserInfo);
                    }
                }

            }
            
            // Check all attributes to retrive the user and ulimatelly check using LDAP
            foreach ( $validUserIdentifierFields as $userIdentifier ) {

                // Fist check for attributes in the datbase using Model
                if ( $model = $possibleModel->where( $userIdentifier, $credentials[ 'any' ] )->newQuery()->first() ) {

                    return $model;

                } else {

                    // Ldap auth and make new model
                    $user = $credentials[ 'any' ];

                    
                    if ( ! isset($user) ) {
                        throw new InvalidArgumentException;
                    }

                    // Get the info for the user from AD over LDAP
                    $infoCollection = $this->ad->user()->infoCollection( $user, array('*') );

                    if ( $infoCollection ) {

                        $ldapUserInfo = $this->setInfoArray($infoCollection);

                        return new \petruavram\OrchestraAuthLdap\User((array) $ldapUserInfo);

                    } else {
                        return false;
                    }
                }
            }

        } else {

            foreach ( $credentials as $key => $credential ) {
                // If the auth identifier by which we login is specified we'll use that 

                if ( in_array( $key,  $validUserIdentifierFields ) ) {

                    if ( $key == 'ldap' ) {
                        // Ldap auth and make new model

                        $infoCollection = $this->ad->user()->infoCollection( $credential, array('*') );

                        if ( $infoCollection ) {
                            $ldapUserInfo = $this->setInfoArray($infoCollection);

                            return new \petruavram\OrchestraAuthLdap\User((array) $ldapUserInfo);
                        }

                    }

                    if ( $key != 'password' ) {

                        if ( $model = $possibleModel->where( $key, $credential )->newQuery()->first() ) {
                            return $model;
                        }

                    }
                }
            }
        }
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  Illuminate\Auth\UserInterface  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(UserInterface $user, array $credentials)
    {
       
        // get he user credentials form settings
        $userCredentialsID = $this->getUsernameField();
        // Check which ones are usable for this model
        $validUserIdentifierFields = $this->validUsernameFields( $userCredentialsID );

        // A model to work with for retriveing via model auth
        $possibleModel = $this->createModel();

        // If the credential given is 'any' we'll check all auth scenarious based on the settings and use the model 
        // based auth method first
        if ( array_key_exists( 'any', $credentials ) ) {
            
            // The default 
            if ( array_key_exists( 'default', $validUserIdentifierFields ) ) {

                 $userCredential = $validUserIdentifierFields['default'];

                // Try the default attribute from the model to retrive the user
                if ( $model = $possibleModel->where( $userCredential, $credentials[ 'any' ] )->newQuery()->first() ) {

                    return $this->hasher->check( $credentials['password'], $user->getAuthPassword() );

                } else {

                    // Ldap auth and make new model
                    $user = $credentials[ 'any' ];

                    
                    if ( ! isset($user) ) {
                        throw new InvalidArgumentException;
                    }

                    // Get the info for the user from AD over LDAP
                    $infoCollection = $this->ad->user()->infoCollection( $user, array('*') );

                    if ( $infoCollection ) {

                        $ldapUserInfo = $this->setInfoArray($infoCollection);

                        $authenticated = $this->ad->authenticate( $credentials[ 'any' ], $credentials['password'] );

                        if ( $authenticated == true ) {
                            return $authenticated;
                        }
                    }
                }
            }
                
            foreach ( $validUserIdentifierFields as $userIdentifier ) {

                if ( $model = $possibleModel->where( $userCredential, $credentials[ 'any' ] )->newQuery()->first() ) {
                    return $this->hasher->check( $credentials['password'], $user->getAuthPassword() );
                } else {

                    // Ldap auth and make new model
                    return $this->ad->authenticate( $credentials[ 'any' ], $credentials['password'] );

                }

            }

        } else {

            foreach ( $credentials as $key => $credential ) {

                // If the auth identifier by which we login is specified we'll use that 
                if ( in_array( $key,  $validUserIdentifierFields ) ) {

                    if ( $key == 'ldap' ) {
                        // Ldap auth and make new model

                        $infoCollection = $this->ad->user()->infoCollection( $credential, array('*') );

                        if ( $infoCollection ) {
                            $ldapUserInfo = $this->setInfoArray($infoCollection);

                            return $this->ad->authenticate($credentials['ldap'], $credentials['password']);
                        }

                    }

                    if ( $key == 'password' ) {

                        return $this->hasher->check( $credential, $user->getAuthPassword() );

                    }
                }
            }
        }   
    }
    
    /**
     * Build the array sent to GenericUser for use in Auth::user()
     * 
     * @param adLDAP\adLDAP $infoCollection
     * @return array $info
     */
    protected function setInfoArray($infoCollection)
    {
        /*
        * in app/auth.php set the fields array with each value
        * as a field you want from active directory
        * If you have 'user' => 'samaccountname' it will set the $info['user'] = $infoCollection->samaccountname
        * refer to the adLDAP docs for which fields are available.
        */

        if ( ! empty($this->config['fields'])) {
            foreach ($this->config['fields'] as $k => $field) {
                if ($k == 'groups') {
                    $info[$k] = $this->getAllGroups($infoCollection->memberof);
                } elseif ($k == 'primarygroup') {
                    $info[$k] = $this->getPrimaryGroup($infoCollection->distinguishedname);
                } else {
                    $info[$k] = $infoCollection->$field;
                }
            }
            
        } else {
            //if no fields array present default to username and displayName
            $info['username'] = $infoCollection->samaccountname;
            $info['displayname'] = $infoCollection->displayName;
            $info['primarygroup'] = $this->getPrimaryGroup($infoCollection->distinguishedname);
            $info['groups'] = $this->getAllGroups($infoCollection->memberof);
        }
        
        /*
        * I needed a user list to populate a dropdown
        * Set userlist to true in app/config/auth.php and set a group in app/config/auth.php as well
        * The table is the OU in Active directory you need a list of.
        */
        if ( ! empty($this->config['userList'])) {
            $info['userlist'] = $this->ad->folder()->listing(array($this->config['group']));
        }

        return $info;
    }

    /**
     * Makes an user model form the string speficied in c-tor args
     * @return Illuminate\Auth\UserInterface
     */
    public function createModel()
    {   
        $model = '\\' . ltrim($this->model, '\\');
        
        return new $model;
    }

    /**
     * Add Ldap fields to current user model.
     * 
     * @param Illuminate\Auth\UserInterface $model
     * @param adLDAP\collection\adLDAPCollection $ldap
     * @return Illuminate\Auth\UserInterface
     */
    protected function addLdapToModel($model, $ldap)
    {
        $combined = $ldap + $model->getAttributes();

        return $model->fill($combined);
    }

    /**
     * Return Primary Group Listing
     * @param  array $groupList 
     * @return string
     */
    protected function getPrimaryGroup($groupList)
    {
        $groups = explode(',', $groupList);

        return substr($groups[1], '3');
    }

    /**
     * Return list of groups (except domain and suffix)
     * @param  array $groups 
     * @return array
     */
    protected function getAllGroups($groups) 
    {
        $grps = '';
        if ( ! is_null($groups) ) {
            if (!is_array($groups)) {
                $groups = explode(',', $groups);
            }
            foreach ($groups as $k => $group) {
                $splitGroups = explode(',', $group);
                foreach ($splitGroups as $splitGroup) {
                    if (substr($splitGroup,0, 3) !== 'DC=') {
                        $grps[substr($splitGroup, '3')] = substr($splitGroup, '3');
                    }
                }
            }
        }

        return $grps;
    }

    /**
     * Gets the current model name string
     * @return type
     */
    public function getModel()
    {
        return $this->model;
    }

    protected function getUsernameField()
    {
        if ( isset($this->config['identifiers']) && isset($this->config['default_identifier']) ) {
            $idFields = array();

            $defaultIdentifier = $this->config['default_identifier'];

            foreach ( $this->config['identifiers'] as $key => $identifier) {

                if ( $key == $defaultIdentifier ) {
                    $idFields['default'] = $identifier;
                } else {
                    $idFields[$key] = $identifier;
                }
            }

            return $idFields;

        } else if ( isset($this->config['default_identifier']) ) {

            $defaultIdentifier = $this->config['default_identifier'];

            return  $defaultIdentifier;
        } else {
            return 'username';
        }
    }

    /**
     * Check if field is present in the model used for authentification
     * @return bool
     */
    protected function checkField( $field ) {

        $columns = DB::select('SHOW COLUMNS FROM `' . $this->createModel()->getTable() . '`');
        $fields = array();
        foreach($columns as $col){
            $fields[] = $col->Field;
        }

        if ( in_array( $field, $fields ) ) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Return an array with all the fields that exists in the model that can be
     * used as username from the identifiers config auth option
     *
     * @param mixed $fields - an array of strings or string with the identifiers from auth setting
     * @return a a
     */
    protected function validUsernameFields( $identifierFields ) {
               
        $resultsArr = array();

        // Verify if the identifier field(s) given are present in the model
        if ( ! is_array( $identifierFields ) ) {        // For 1 identifier

            if ( $this->checkField( $identifierFields ) ) {

                $resultsArr['default'] = $identifierFields;
                
            }
            
        } else {                                        // For many identifiers

            foreach ( $identifierFields as $key => $identifierField ) {

                if ( $this->checkField( $identifierField ) ) {

                    $resultsArr[$key] = $identifierField;
                }
            }
        }

        return $resultsArr;
    }
}
