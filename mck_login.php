<?php
/**
 * Handles site-wide logins, sessions and self-registering
 *
 * @package mck_login
 * @author Casalegno Marco <http://www.kreatore.it/>
 * @author Jukka Svahn <http://rahforum.biz>
 * @license GNU GPLv2
 * @link http://www.kreatore.it/txp/mck_login
 * @link https://github.com/gocom/mck_login
 *
 * Requires Textpattern v4.4.1 (or newer) and PHP v5.2 (or newer)
 */

/**
 * Handles form validation and saving, all of the non-tag stuff
 */

class mck_login
{
    public static $form_errors = array();
    public static $action;

    /**
     * Constructor.
     */

    public function __construct()
    {
        if (!defined('mck_login_pub_path')) {
            define('mck_login_pub_path', preg_replace('|//$|', '/', rhu.'/'));
        }

        if (!defined('mck_login_admin_path')) {
            define('mck_login_admin_path', '/textpattern/');
        }

        if (!defined('mck_login_admin_domain')) {
            define('mck_login_admin_domain', '');
        }

        register_callback(array($this, 'logInHandler'), 'textpattern');
        register_callback(array($this, 'logOutHandler'), 'textpattern');
        register_callback(array($this, 'confirmResetHandler'), 'textpattern');
    }

    /**
     * Add and get form validation errors
     * @param string $message Either l10n string, or single line of text
     * @param string $type For which form the error is for.
     * @return array
     * <code>
     *        mck_login::error('abc_l10n_string');
     * </code>
     */

    public static function error($message = null, $type = null)
    {
        if (!$type) {
            $type = self::$action;
        }

        if ($type !== null && !isset(self::$form_errors[$type])) {
            self::$form_errors[$type] = array();
        }

        if ($message !== null) {
            self::$form_errors[$type][] = $message;
        }

        return isset(self::$form_errors[$type]) ? self::$form_errors[$type] : array();
    }

    /**
     * Log out handler.
     */

    public function logOutHandler()
    {
        $user = is_logged_in();

        if ($logout = gps('mck_logout') && $user && self::$action = 'logout') {
            callback_event('mck_login.logout');

            safe_update(
                'txp_users',
                "nonce = '".doSlash(md5(uniqid(mt_rand(), true)))."'",
                "name = '".doSlash($user['name'])."'"
            );

            setcookie('txp_login_public', '', time() - 3600, mck_login_pub_path);
            setcookie('txp_login', '', time() - 3600, mck_login_admin_path, mck_login_admin_domain);
            unset($_COOKIE['txp_login_public']);
        }
    }

    /**
     * Log in handler.
     */

    public function logInHandler()
    {
        callback_event('mck_login.login', '', 1);

        extract(doArray(
            array(
                'name' => ps('mck_login_name'),
                'pass' => ps('mck_login_pass'),
                'stay' => ps('mck_login_stay'),
                'form' => ps('mck_login_form'),
            ),
            'trim')
        );

        if ($form && !is_logged_in() && strpos($form, ';') && self::$action = 'login') {
            callback_event('mck_login.login');

            if (!$pass || !$name) {
                self::error('name_and_pass_required');
                return;
            }

            $form = explode(';', (string) $form);

            if ($form[1] != md5($form[0] . get_pref('blog_uid'))) {
                self::error('invalid_token');
                return;
            }

            $time = strtotime('-30 minutes');
            if (($time != false) && (int) $form[0] < $time) {
                self::error('form_expired');
                return;
            }

            include_once txpath . '/lib/txplib_admin.php';
            include_once txpath . '/include/txp_auth.php';

            if (txp_validate($name, $pass, false) === false) {
                callback_event('mck_login.invalid_login');
                self::error('invalid_login');
                sleep(3);
                return;
            }

            $c_hash = md5(uniqid(mt_rand(), true));
            $nonce = md5($name.pack('H*', $c_hash));
            $value = substr(md5($nonce), -10).$name;
            $privs = fetch('privs', 'txp_users', 'name', $name);

            safe_update(
                'txp_users',
                "nonce = '".doSlash($nonce)."', last_access = now()",
                "name = '".doSlash($name)."'"
            );

            setcookie(
                'txp_login_public',
                $value,
                $stay ? time()+3600*24*30 : 0,
                mck_login_pub_path
            );

            if ($privs > 0) {
                setcookie('txp_login', $name.','.$c_hash, $stay ? time() + 3600*24*365 : 0, mck_login_admin_path, mck_login_admin_domain);
            }

            $_COOKIE['txp_login_public'] = $value;
            callback_event('mck_login.logged_in');
        }
    }

    /**
     * Reset password.
     */

    public function confirmResetHandler()
    {
        if (($reset = gps('mck_reset')) && !is_logged_in()) {
            self::$action = 'reset';

            callback_event('mck_login.reset_confirm');

            sleep(3);

            $confirm = pack('H*', $reset);
            $reset = substr($confirm, 5);

            if (!strpos($reset, ';')) {
                self::error('invalid_token');
                return;
            }

            $name = explode(';', $reset);
            $redirect = array_pop($name);
            $name = implode(';', $name);

            $r =
                                safe_row(
                                    'nonce, email, RealName',
                                    'txp_users',
                                    "name = '".doSlash($name)."'"
                                );

            $packed = pack('H*', substr(md5($r['nonce'] . $redirect), 0, 10)) . $name . ';' . $redirect;

            if (!$r || !$r['nonce'] || $confirm !== $packed) {
                sleep(3);
                self::error('invalid_token');
                return;
            }

            include_once txpath . '/lib/txplib_admin.php';
            include_once txpath . '/include/txp_auth.php';

            $password = Txp::get('\Textpattern\Password\Random')->generate(PASSWORD_LENGTH);
            $hash = Txp::get('\Textpattern\Password\Hash')->hash($password);
            $nonce = md5($name.pack('H*', md5(uniqid(mt_rand(), true))));

            if (
                safe_update(
                    'txp_users',
                    "pass = '".doSlash($hash)."',
                     nonce = '".doSlash($nonce)."'",
                    "name = '".doSlash($name)."'"
                ) === false
            ) {
                self::error('saving_failed');
                return;
            }

            $authorLang = safe_field(
                'val',
                'txp_prefs',
                "name = 'language_ui' AND user_name = '".doSlash($name)."'"
            );
            $authorLang = ($authorLang) ? $authorLang : TEXTPATTERN_DEFAULT_LANG;

            $txpLang = Txp::get('\Textpattern\L10n\Lang');
            $txpLang->swapStrings($authorLang, 'admin, common');

            $message = gTxt('salutation', array('{name}' => $r['RealName'])).n.n.
                       gTxt('your_login_is').': '.$name.n.n.
                       gTxt('your_password_is').': '.$password.n.n.
                       gTxt('log_in_at').': '.hu.$redirect;

            $subject = gTxt(
                           'mck_login_your_new_password',
                           array('{sitename}' => get_pref('sitename'))
                       );

            $txpLang->swapStrings(null);

            $sender_email = get_pref('smtp_from');

            if (is_valid_email($sender_email)) {
                $sent = txpMail($r['email'], $subject, $message, $sender_email);
            } else {
                $sent = txpMail($r['email'], $subject, $message);
            }

            if ($sent === false) {
                self::error('could_not_mail');
                return;
            }

            callback_event('mck_login.reset_confirmed');

            header('Location: '.hu.$redirect);

            $msg = gTxt('mck_login_redirect_message', array('{url}' => htmlspecialchars(hu.$redirect)));
            die($msg);
        }
    }

    /**
     * Send password reset confirmation message
     * @param array $atts
     * @return bool
     * @access private
     */

    public static function send_reset($atts)
    {
        extract(doArray(array(
                        'name' => ps('mck_reset_name'),
                        'form' => ps('mck_reset_form'),
                ), 'trim'));

        $is_logged_in = mck_login(true) !== false;

        if (!$form || !strpos($form, ';') || $is_logged_in) {
            return false;
        }

        self::$action = 'reset';

        callback_event('mck_login.reset');

        $form = explode(';', (string) $form);

        if ($form[1] != md5($form[0] . get_pref('blog_uid'))) {
            self::error('invalid_token');
            return false;
        }

        $time = strtotime('-30 minutes');
        if (($time != false) && (int) $form[0] < $time) {
            self::error('form_expired');
            return false;
        }

        $r = safe_row(
            'email, nonce, RealName',
            'txp_users',
            "name = '".doSlash($name)."'"
        );

        if (!$r) {
            self::error('invalid_username');
            return false;
        }

        $confirm = bin2hex(
            pack('H*', substr(md5($r['nonce'] . $atts['go_to_after']), 0, 10)).
                $name . ';' . $atts['go_to_after']
        );

        $authorLang = safe_field('val', 'txp_prefs', "name='language_ui' AND user_name = '".doSlash($name)."'");
        $authorLang = ($authorLang) ? $authorLang : TEXTPATTERN_DEFAULT_LANG;

        $txpLang = Txp::get('\Textpattern\L10n\Lang');
        $txpLang->swapStrings($authorLang, 'admin, common');

        $subject = '['.get_pref('sitename').'] '.gTxt('password_reset_confirmation_request');
        $message = gTxt('salutation', array('{name}' => $r['RealName'])).n.n.
                   gTxt('password_reset_confirmation').n.n.
                   hu.'?mck_reset='.$confirm;

        $txpLang->swapStrings(null);

        $sender_email = get_pref('smtp_from');

        if (is_valid_email($sender_email)) {
            $sent = txpMail($r['email'], $subject, $message, $sender_email);
        } else {
            $sent = txpMail($r['email'], $subject, $message);
        }

        if ($sent === false) {
            self::error('could_not_mail');
            return false;
        }

        callback_event('mck_login.reset_sent');
        return true;
    }

    /**
     * Save a new user
     * @param array $atts
     * @return bool
     * @see generate_password(), txp_hash_password()
     * @access private
     */

    public static function add_user($atts)
    {
        callback_event('mck_login.register', '', 1);

        extract(doArray(
            array(
                'email' => ps('mck_register_email'),
                'name' => ps('mck_register_name'),
                'RealName' => ps('mck_register_realname'),
                'form' => ps('mck_register_form'),
            ),
            'trim')
        );

        if (!$form || !strpos($form, ';')) {
            return false;
        }

        self::$action = 'register';

        callback_event('mck_login.register');

        if (self::$form_errors) {
            return false;
        }

        $ip = remote_addr();

        if (is_blocklisted($ip)) {
            self::error('ip_blocklisted');
            return false;
        }

        if (!$email || !$name || !$RealName) {
            self::error('all_fields_required');
            return false;
        }

        $form = explode(';', (string) $form);

        if ($form[1] != md5($form[0].get_pref('blog_uid'))) {
            self::error('invalid_token');
            return false;
        }

        $time = strtotime('-30 minutes');
        if (($time != false) && (int) $form[0] < $time) {
            self::error('form_expired');
            return false;
        }

        if (self::field_strlen($email) > 100) {
            self::error('email_too_long');
        } elseif (!is_valid_email($email)) {
            self::error('invalid_email');
        }

        if (self::field_strlen($name) < 3) {
            self::error('username_too_short');
        } elseif (self::field_strlen($name) > 64) {
            self::error('username_too_long');
        }

        if (self::field_strlen($RealName) > 64) {
            self::error('realname_too_long');
        }

        if (self::error()) {
            return false;
        }

        if (
            safe_row(
                'name',
                'txp_users',
                "name = '".doSlash($name)."' OR email = '".doSlash($email)."' LIMIT 0, 1"
            )
        ) {
            if (fetch('email', 'txp_users', 'email', $email)) {
                self::error('email_in_use');
            }

            /* -- removed
             *    self::error('username_taken');
             */
            // -- FIX: spit error only if username already exists
            if (fetch('name', 'txp_users', 'name', $name)) {
                self::error('username_taken');
            }

            return false;
        }

        sleep(3);

        include_once txpath . '/lib/txplib_admin.php';
        include_once txpath . '/include/txp_auth.php';

        $privs = (int) $atts['privs'];

        $password = Txp::get('\Textpattern\Password\Random')->generate(PASSWORD_LENGTH);

        if (
            create_user($name, $email, $password, $RealName, $privs)
             === false
        ) {
            self::error('saving_failed');
            return false;
        }

        $authorLang = safe_field('val', 'txp_prefs', "name='language_ui' AND user_name = '".doSlash($name)."'");
        $authorLang = ($authorLang) ? $authorLang : TEXTPATTERN_DEFAULT_LANG;

        $txpLang = Txp::get('\Textpattern\L10n\Lang');
        $txpLang->swapStrings($authorLang, 'admin, common');

        $subject = '['.get_pref('sitename').'] '.gTxt('your_new_password');
        $message = gTxt('salutation', array('{name}' => $RealName)).n.n.
                   gTxt('your_login_is').': '.$name.n.n.
                   gTxt('your_password_is').': '.$password.n.n.
                   gTxt('log_in_at').': '.$atts['log_in_url'];

        $txpLang->swapStrings(null);

        $sender_email = get_pref('smtp_from');

        if (is_valid_email($sender_email)) {
            $sent = txpMail($email, $subject, $message, $sender_email);
        } else {
            $sent = txpMail($email, $subject, $message);
        }

        if ($sent === false) {
            self::error('could_not_mail');
            return false;
        }

        callback_event('mck_login.registered');
        return true;
    }

    /**
     * Save a new password
     * @return bool
     * @see txp_validate(), txp_hash_password()
     * @access private
     */

    public static function save_password()
    {
        extract(doArray(
            array(
                'old_pass' => ps('mck_password_old'),
                'new_pass' => ps('mck_password_new'),
                'confirm_pass' => ps('mck_password_confirm'),
                'token' => ps('mck_login_token'),
                'form' => ps('mck_password_form'),
            ),
            'trim')
        );

        if (!$form || mck_login(true) === false) {
            return false;
        }

        self::$action = 'password';

        callback_event('mck_login.save_password');

        if (self::error()) {
            return false;
        }

        if (!$old_pass || !$new_pass) {
            self::error('all_fields_required');
            return false;
        }

        if ($token != mck_login_token()) {
            self::error('invalid_csrf_token');
            return false;
        }

        $length = function_exists('mb_strlen') ?
                        mb_strlen($new_pass, 'UTF-8') : strlen($new_pass);

        if (6 > $length) {
            self::error('password_too_short');
        }

        if ($confirm_pass && ($new_pass !== $confirm_pass)) {
            self::error('passwords_do_not_match');
        }

        $name = mck_login(array('name' => 'name'));

        include_once txpath.'/lib/txplib_admin.php';
        include_once txpath.'/include/txp_auth.php';

        if (txp_validate($name, $old_pass, false) === false) {
            self::error('old_password_incorrect');
            sleep(3);
        }

        if (self::error()) {
            return false;
        }

        if (
            change_user_password($name, $new_pass) === false
        ) {
            self::error('saving_failed');
            return false;
        }

        callback_event('mck_login.password_saved');
    }

    /**
     * Get string length for pre-save validation.
     * @param string $str
     * @return int
     * @see DB::DB()
     * @access private
     */

    public static function field_strlen($str)
    {
        return Txp::get('\Textpattern\Type\StringType', $str)->getLength();
    }
}

new mck_login();

// Register public tags (txp 4.7+)
if (class_exists("\Textpattern\Tag\Registry")) {
    Txp::get("\Textpattern\Tag\Registry")
        ->register("mck_login")
        ->register("mck_login_if")
        ->register("mck_login_form")
        ->register("mck_register_form")
        ->register("mck_password_form")
        ->register("mck_reset_form")
        ->register("mck_login_input")
        ->register("mck_login_errors")
        ->register("mck_login_token")
        ->register("mck_login_bouncer");
}

/**
 * Password reset form
 * @param array $atts
 * @param string $atts[action] Form's action (target location)
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $atts[go_to_after] The page (page) the confirmation URL directs users. i.e. about/reset-page
 * @param string $atts[subject] Confirmation email's subject.
 * @param string $thing
 * @return string HTML markup
 * <code>
 *        <txp:mck_reset_form>
 *            <txp:mck_login_errors />
 *            <txp:mck_login_input type="text" name="mck_reset_name" />
 *            <button type="submit">Send reset request</button>
 *        <txp:else />
 *            Confirmation email has been sent with a reset link.
 *        </txp:mck_reset_form>
 * </code>
 */

function mck_reset_form($atts, $thing = '')
{
    global $pretext, $sitename;

    $opt = lAtts(array(
                'action' => $pretext['request_uri'] . '#mck_reset_form',
                'id' => 'mck_reset_form',
                'class' => 'mck_reset_form',
                'go_to_after' => '',
                'subject' => '['.$sitename.'] '.gTxt('password_reset_confirmation_request'),
        ), $atts);

    if (mck_login(true) !== false) {
        return;
    }

    $r = mck_login::send_reset($opt);
    extract($opt);

    if ($r === true && !mck_login::error()) {
        return parse($thing, false);
    }

    $token = ps('mck_reset_form');

    if (!$token || !mck_login::error()) {
        $timestamp = strtotime('now');
        $token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
    }

    if (mck_login::error()) {
        $class .= ' mck_login_error';
    }

    mck_login_errors('reset');

    $r =
        '<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
                hInput('mck_reset_form', $token).n.
                parse($thing, true).n.
                callback_event('mck_login.reset_form').
        '</form>';

    mck_login_errors(null);
    return $r;
}

/**
 * Return user data
 * @param array|bool $atts
 * @param string $atts[name] Options: name, RealName, email, privs.
 * @param bool $atts[escape] Convert special characters to HTML entities.
 * @return mixed
 * @see is_logged_in()
 * <code>
 *        <txp:mck_login name="email" />
 * </code>
 */

function mck_login($atts)
{
    static $data = null;

    if ($data === null) {
        $data = is_logged_in();
    }

    if ($atts === true) {
        return $data;
    }

    extract(lAtts(
        array(
                'name' => 'RealName',
                'escape' => 1,
        ),
        $atts)
    );

    if (!$data || !isset($data[$name])) {
        return;
    }

    return $escape ? htmlspecialchars($data[$name]) : $data[$name];
}

/**
 * Check if the user is logged in, or that the specified value matches.
 *
 * If used as a self-closing single tag, will display 401 error page
 * on failure.
 *
 * @param  array  $atts
 * @param  string $atts[name]  If NULL, checks if visitor is logged in.
 * @param  string $atts[value] Match to.
 * @param  string $thing
 * @return string
 * @see    mck_login()
 * @example
 * &lt;txp:mck_login_if&gt;
 *     User is logged in.
 * &lt;txp:else /&gt;
 *     User is not logged in.
 * &lt;/txp:mck_login_if&gt;
 */

function mck_login_if($atts, $thing = null)
{
    extract(lAtts(
        array(
            'name'  => null,
            'value' => '',
        ),
        $atts)
    );

    $r = ($data = mck_login(true)) !== false && ($name === null || isset($data[$name]) && $data[$name] === $value);

    if ($thing !== null) {
        return parse($thing, $r);
    }

    if ($r === false) {
        txp_die(gTxt('auth_required'), 401);
    }
}

/**
 * Register form
 * @param array $atts
 * @param int $atts[privs] Privileges the user is created with.
 * @param string $atts[action] Form's action (target location).
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $atts[log_in_url] "Log in at" URL used in the sent email.
 * @param string $atts[subject] Email message's subject.
 * @param string $thing
 * @return string HTML markup.
 * <code>
 *        <txp:mck_register_form>
 *            <txp:mck_login_errors />
 *            <txp:mck_login_input type="text" name="mck_register_email" />
 *            <txp:mck_login_input type="text" name="mck_register_name" />
 *            <txp:mck_login_input type="text" name="mck_register_realname" />
 *            <button type="submit">Register</button>
 *        <txp:else />
 *            Email sent with your login details.
 *        </txp:mck_register_form>
 * </code>
 */

function mck_register_form($atts, $thing = '')
{
    global $pretext, $sitename;

    $opt = lAtts(
        array(
            'privs' => 0,
            'action' => $pretext['request_uri'].'#mck_register_form',
            'id' => 'mck_register_form',
            'class' => 'mck_register_form',
            'log_in_url' => hu,
            'subject' => '['.$sitename.'] '.gTxt('your_new_password'),
        ),
        $atts
    );

    $r = mck_login::add_user($opt);
    extract($opt);

    if ($r === true && !mck_login::error()) {
        return parse($thing, false);
    }

    $token = ps('mck_register_form');

    if (!$token || mck_login::error()) {
        $timestamp = strtotime('now');
        $token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
    }

    if (mck_login::error()) {
        $class .= ' mck_login_error';
    }

    mck_login_errors('register');

    $r =
        '<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
                hInput('mck_register_form', $token).n.
                parse($thing, true).n.
                callback_event('mck_login.register_form').
        '</form>';

    mck_login_errors(null);

    return $r;
}

/**
 * Displays a login form
 * @param array $atts
 * @param string $atts[action] Form's action (target location).
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $thing
 * @return string HTML markup.
 * <code>
 *        <txp:mck_login_form>
 *            <txp:mck_login_errors />
 *            <txp:mck_login_input type="text" name="mck_login_name" />
 *            <txp:mck_login_input type="password" name="mck_login_pass" />
 *            <button type="submit">Log in</button>
 *        <txp:else />
 *            You are logged in. <a href="?mck_logout=1">Log out</a>.
 *        </txp:mck_login_form>
 * </code>
 */

function mck_login_form($atts, $thing = '')
{
    global $pretext;

    extract(lAtts(
        array(
            'action' => $pretext['request_uri'].'#mck_login_form',
            'id' => 'mck_login_form',
            'class' => 'mck_login_form',
        ),
        $atts)
    );

    if (mck_login(true) !== false) {
        return parse($thing, false);
    }

    $token = ps('mck_login_form');

    if (!$token || mck_login::error()) {
        $timestamp = strtotime('now');
        $token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
    }

    if (mck_login::error()) {
        $class .= ' mck_login_error';
    }

    mck_login_errors('login');

    $thing =
        '<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
                hInput('mck_login_form', $token).n.
                parse($thing, true).n.
                callback_event('mck_login.login_form').
        '</form>';

    mck_login_errors(null);

    return $thing;
}

/**
 * Displays password changing form.
 *
 * @param  array  $atts
 * @param  string $atts[action] Form's action (target location)
 * @param  string $atts[id]     Form's HTML id
 * @param  string $atts[class]  Form's HTML class
 * @param  string $thing
 * @return string HTML markup
 * @example
 * &lt;txp:mck_password_form&gt;
 *     &lt;txp:mck_login_errors /&gt;
 *     &lt;txp:mck_login_input type="password" name="mck_password_old" /&gt;
 *     &lt;txp:mck_login_input type="password" name="mck_password_new" /&gt;
 *     &lt;txp:mck_login_input type="password" name="mck_password_confirm" /&gt;
 *     &lt;button type="submit"&gt;Save new password&lt;/button&gt;
 * &lt;txp:else /&gt;
 *     Password changed.
 * &lt;/txp:mck_password_form&gt;
 */

function mck_password_form($atts, $thing = '')
{
    global $pretext;

    extract(lAtts(
        array(
            'action' => $pretext['request_uri'].'#mck_password_form',
            'id'     => 'mck_password_form',
            'class'  => 'mck_password_form',
        ),
        $atts)
    );

    if (mck_login(true) === false) {
        return;
    }

    $r = mck_login::save_password();

    if ($r === true && !mck_login::error()) {
        return parse($thing, false);
    }

    if (mck_login::error()) {
        $class .= ' mck_login_error';
    }

    mck_login_errors('password');

    $thing = tag_start('form', array(
            'method' => 'post',
            'action' => $action,
            'id'     => $id,
            'class'  => $class,
        )).
        hInput('mck_login_token', mck_login_token()).
        hInput('mck_password_form', 1).
        parse($thing, true).
        callback_event('mck_login.password_form').
        tag_end('form');

    mck_login_errors(null);
    return $thing;
}

/**
 * Renders a HTML form input.
 *
 * @param  array  $atts Attributes
 * @return string HTML markup
 * @example
 * &lt;txp:mck_login_input type="text" name="foo" value="bar" /&gt;
 */

function mck_login_input($atts)
{
    static $uid = 1;

    $r = lAtts(
        array(
            'type'     => 'text',
            'name'     => '',
            'value'    => '',
            'class'    => 'mck_login_input',
            'id'       => '',
            'label'    => '',
            'required' => 1,
            'remember' => 1,
            'reveal'   => 0,
        ),
        $atts, false
    );

    extract($r);

    $postamble = $wrapstart = $wrapend = '';

    if ($type == 'token') {
        return hInput('mck_login_token', mck_login_token());
    }

    if ($type == 'password') {
        $r['class'] .= ' mck_login_pass';

        if ($r['reveal']) {
            $postamble .= '<div class="accessibility" id="mck_login_announce" aria-live="assertive"></div>';
            $postamble .= Txp::get('\Textpattern\UI\Style')->setContent(<<<EOCSS
.mck_login_pw_wrapper { display: inline-flex; }
.mck_input_toggle { position: relative; display: flex; justify-content: center; align-items: center; box-shadow: unset; border-radius: 0; border-inline-start: 0; }
.mck_input_toggle:active { top: unset; }
.mck_input_toggle[aria-pressed="true"]  .show-pw { display: none; }
.mck_input_toggle[aria-pressed="false"] .hide-pw { display: none; }
EOCSS);
            $postamble .= script_js(
                <<<EOJS
const mck_login_inputWrapper = document.querySelector('.mck_login_pw_wrapper');
const mck_login_pWord = document.querySelector('[name="mck_password_new"]');
const mck_login_pWord_id = mck_login_pWord.id;
const mck_login_announce = document.getElementById('mck_login_announce');
const mck_login_toggleBtnHTML = `<button class="mck_input_toggle" type="button" id="mck_login_password_toggle" aria-pressed="false" aria-controls="`+mck_login_pWord_id+`" type="button">
<svg class="show-pw" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 2c1.981 0 3.671.992 4.933 2.078 1.27 1.091 2.187 2.345 2.637 3.023a1.62 1.62 0 0 1 0 1.798c-.45.678-1.367 1.932-2.637 3.023C11.67 13.008 9.981 14 8 14c-1.981 0-3.671-.992-4.933-2.078C1.797 10.83.88 9.576.43 8.898a1.62 1.62 0 0 1 0-1.798c.45-.677 1.367-1.931 2.637-3.022C4.33 2.992 6.019 2 8 2ZM1.679 7.932a.12.12 0 0 0 0 .136c.411.622 1.241 1.75 2.366 2.717C5.176 11.758 6.527 12.5 8 12.5c1.473 0 2.825-.742 3.955-1.715 1.124-.967 1.954-2.096 2.366-2.717a.12.12 0 0 0 0-.136c-.412-.621-1.242-1.75-2.366-2.717C10.824 4.242 9.473 3.5 8 3.5c-1.473 0-2.825.742-3.955 1.715-1.124.967-1.954 2.096-2.366 2.717ZM8 10a2 2 0 1 1-.001-3.999A2 2 0 0 1 8 10Z"></path></svg>
<svg class="hide-pw" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M.143 2.31a.75.75 0 0 1 1.047-.167l14.5 10.5a.75.75 0 1 1-.88 1.214l-2.248-1.628C11.346 13.19 9.792 14 8 14c-1.981 0-3.67-.992-4.933-2.078C1.797 10.832.88 9.577.43 8.9a1.619 1.619 0 0 1 0-1.797c.353-.533.995-1.42 1.868-2.305L.31 3.357A.75.75 0 0 1 .143 2.31Zm1.536 5.622A.12.12 0 0 0 1.657 8c0 .021.006.045.022.068.412.621 1.242 1.75 2.366 2.717C5.175 11.758 6.527 12.5 8 12.5c1.195 0 2.31-.488 3.29-1.191L9.063 9.695A2 2 0 0 1 6.058 7.52L3.529 5.688a14.207 14.207 0 0 0-1.85 2.244ZM8 3.5c-.516 0-1.017.09-1.499.251a.75.75 0 1 1-.473-1.423A6.207 6.207 0 0 1 8 2c1.981 0 3.67.992 4.933 2.078 1.27 1.091 2.187 2.345 2.637 3.023a1.62 1.62 0 0 1 0 1.798c-.11.166-.248.365-.41.587a.75.75 0 1 1-1.21-.887c.148-.201.272-.382.371-.53a.119.119 0 0 0 0-.137c-.412-.621-1.242-1.75-2.366-2.717C10.825 4.242 9.473 3.5 8 3.5Z"></path></svg>
<span class="accessibility">Show/hide password</span>
</button>`;

mck_login_inputWrapper.insertAdjacentHTML('beforeend', mck_login_toggleBtnHTML);
const toggleBtn = document.getElementById('mck_login_password_toggle');
mck_login_inputWrapper.setAttribute('role', 'group');
mck_login_inputWrapper.setAttribute('aria-labelledby', mck_login_pWord_id);

toggleBtn.addEventListener('click', () => {
    if (toggleBtn.getAttribute('aria-pressed') === 'false') {
        toggleBtn.setAttribute('aria-pressed', 'true');
        mck_login_pWord.setAttribute('type', 'text');
        mck_login_announce.textContent = 'Password is visible';
    } else {
        mck_login_setPasswordDefaults(false);
    }
});

function mck_login_setPasswordDefaults(ignore) {
    toggleBtn.setAttribute('aria-pressed', 'false');
    mck_login_pWord.setAttribute('type', 'password');
    if (!ignore) {
        mck_login_announce.textContent = 'Password is hidden';
    }
}

document.addEventListener("DOMContentLoaded", function() {
    document.getElementById('mck_password_form').querySelector('[type="submit"]').addEventListener('click', () => {
        if (mck_login_pWord.checkValidity() && mck_login_pWord.getAttribute('type') === 'text') {
            mck_login_setPasswordDefaults(true);
        }
    });
});
EOJS
            );
            $wrapstart = '<div class="mck_login_pw_wrapper">';
            $wrapend = '</div>';
        }
    }

    unset($r['reveal']);

    if ($required) {
        $r['class'] .= ' mck_login_required';
    }

    if (isset($_POST[$name])) {
        if ($type == 'checkbox' && ps($name) == $value) {
            $r['checked'] = 'checked';
        }

        if ($type != 'password' && $remember) {
            $r['value'] = ps($name);
        }

        if (ps($name) === '' && $required) {
            $r['class'] .= ' mck_login_error';
        }
    }

    if (!$id && $uid++) {
        $r['id'] = 'mck_login_' . md5($name . $uid);
    }

    if ($label) {
        $label = '<label for="'.txpspecialchars($r['id']).'">'.txpspecialchars($r['label']).'</label>'.n;
    }

    $r = array_merge((array) $atts, (array) $r);
    unset($r['label']);

    if ($required != 'required') {
        unset($r['required']);
    }

    $out = array();

    foreach ($r as $name => $value) {
        if ($value !== '' || $name === 'value') {
            $out[] = txpspecialchars($name).'="'.txpspecialchars($value).'"';
        }
    }

    return $label.$wrapstart.'<input '.implode(' ', $out).'>'.$wrapend.$postamble;
}

/**
 * Displays error messages
 * @param array|string $atts
 * @param string $atts[for] Sets which form's errors are shown. Either login, reset, password, register.
 * @param string $atts[wraptag] HTML wraptag.
 * @param string $atts[break] HTML tag used to separate the items.
 * @param string $atts[class] Wraptag's HTML class.
 * @param int $atts[offset] Skip number of errors from the beginning.
 * @param int $atts[limit] Limit number of shown errors.
 * @return string HTML markup
 * <code>
 *        <txp:mck_login_errors for="reset" wraptag="p" break="" />
 * </code>
 */

function mck_login_errors($atts)
{
    static $parent = null;

    if (is_string($atts) || $atts === null) {
        $parent = $atts;
        mck_login::$action = $atts;
        return;
    }

    extract(lAtts(
        array(
            'for' => $parent,
            'wraptag' => 'ul',
            'break' => 'li',
            'class' => '',
            'offset' => 0,
            'limit' => null,
        ),
        $atts)
    );

    $r = mck_login::error();

    if (!$r) {
        return;
    }

    if ($offset || $limit) {
        $r = array_slice($r, $offset, $limit);
    }

    $out = array();

    foreach ($r as $msg) {
        $pfx = gTxt('mck_login_'.$msg);

        $out[] =
            '<span class="mck_login_error_'.md5($msg).'">'.
                ($pfx == 'mck_login_' . $msg ? gTxt($msg) : $pfx).
            '</span>';
    }

    return $out ? doWrap($out, $wraptag, $break, $class) : '';
}

/**
 * Generate a ciphered token.
 * @return string
 * <code>
 *        <txp:mck_login_token />
 * </code>
 */

function mck_login_token()
{
    static $token;

    if (!$token) {
        $nonce = fetch(
                    'nonce',
                    'txp_users',
                    'name',
                    mck_login(array('name' => 'name'))
                );

        $token = md5($nonce . get_pref('blog_uid'));
    }

    return $token;
}

/**
 * Bouncer. Checks token, and protects against CSRF attempts.
 * @param mixed $void
 * @param string $thing
 * @return mixed
 * <code>
 *        <txp:mck_login_bouncer />
 * </code>
 */

function mck_login_bouncer($void = null, $thing = null)
{
    if (gps('mck_login_token') != mck_login_token()) {
        sleep(3);

        if ($thing !== null) {
            return false;
        }

        txp_die(gTxt('mck_login_invalid_csrf_token'), '401');
    }

    if ($thing !== null && !$void) {
        return parse($thing);
    }
}
