<?php

/**
 * Enqueue script and styles for child theme
 */
function cm_child_enqueue_styles_and_scripts()
{
	wp_enqueue_style('child-styles', get_stylesheet_directory_uri() . '/style.css', false, time(), 'all');
	wp_enqueue_style('cm-elementor-styles', get_stylesheet_directory_uri() . '/css/cm-elementor.css', false, time(), 'all');
	wp_enqueue_script("si_script", get_stylesheet_directory_uri() . "/js/custom.js", '', time());
}
add_action('wp_enqueue_scripts', 'cm_child_enqueue_styles_and_scripts', 110000);

/**
 * Add category column to Woocommerce order details page in admin
 */
function cm_action_woocommerce_admin_order_item_headers()
{ ?>
	<th class="item sortable" colspan="2" data-sort="string-ins"><?php _e('Categoria', 'woocommerce'); ?></th>
<?php
};

function cm_action_woocommerce_admin_order_item_values($_product, $item, $item_id)
{ ?>
	<td class="name" colspan="2">
		<?php
		$category_names = [];
		if ($_product) {
			$termsp = get_the_terms($_product->get_id(), 'product_cat');
			if (!empty($termsp)) {
				foreach ($termsp as $term) {
					$_categoryid = $term->term_id;
					if ($term = get_term_by('id', $_categoryid, 'product_cat')) {
						$category_names[] = $term->name;
					}
				}
			}
		}
		echo implode(', ', $category_names)
		?>
	</td>
<?php
};

add_action('woocommerce_admin_order_item_values', 'cm_action_woocommerce_admin_order_item_values', 10, 3);
add_action('woocommerce_admin_order_item_headers', 'cm_action_woocommerce_admin_order_item_headers', 10, 0);


/**
 * Override osf_single_product_quantity_label with 
 */
remove_action('woocommerce_before_add_to_cart_quantity', 'osf_single_product_quantity_label', 10);
add_action('woocommerce_before_add_to_cart_quantity', 'cm_single_product_quantity_label', 10);
function cm_single_product_quantity_label() {
	global $product;
	$min_value = apply_filters('woocommerce_quantity_input_min', $product->get_min_purchase_quantity(), $product);
	$max_value = apply_filters('woocommerce_quantity_input_max', $product->get_max_purchase_quantity(), $product);
	if ($max_value && $min_value !== $max_value) {
	echo '<label class="quantity_label">' . __('Cantidad:', 'medilazar') . ' </label>';
	}
}

/**
 * Change add to cart button text on single page
 */
function cm_woocommerce_add_to_cart_button_text_single() {
    return __( 'Añadir a la cesta', 'woocommerce' ); 
}
add_filter( 'woocommerce_product_single_add_to_cart_text', 'cm_woocommerce_add_to_cart_button_text_single' ); 


function cm_login_endpoint() {
    add_rewrite_endpoint('direct-login', EP_ROOT);
	flush_rewrite_rules();
}
add_action('init', 'cm_login_endpoint');

add_filter( 'auth_cookie_expiration', function( $duration, $user_id, $remember ) {
    // Set the cookie to expire after 1 day.
    return DAY_IN_SECONDS;
}, 10, 3 );

add_action('init', 'cm_direct_login');
function cm_direct_login() {
    if (isset($_GET['direct-login']) && $_GET['direct-login'] == 'true') {
        $username = sanitize_user($_GET['username']);
        $password = $_GET['password']; // Passwords are hashed in the database, so sanitization is not necessary
        $email = sanitize_email($_GET['useremail']);
        $first_name = sanitize_text_field($_GET['userfname']);
        $last_name = sanitize_text_field($_GET['userlname']);
        $user = wp_authenticate($username, $password);

        if (!is_wp_error($user)) {
            wp_clear_auth_cookie();
            wp_set_current_user($user->ID);		
			wp_set_auth_cookie($user->ID, true);
            // Redirect after successful login
            wp_redirect(home_url());
            exit;
        } else {
            // Handle login error
            wp_redirect(home_url() . '/login-error'); // Redirect to a custom error page
            exit;
        }
    }
}

// Utility functions for encryption and decryption.
// Consider moving these to a separate file if you have a utility or helper class.
function encrypt_data($data, $key, $iv) {
    return openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
}

function decrypt_data($data, $key, $iv) {
    return openssl_decrypt($data, 'aes-256-cbc', $key, 0, $iv);
}

// Securely retrieve encryption key and IV.
// Store these in your wp-config.php or a secure environment variable, not directly in the code.
function get_encryption_key() {
    return defined('ENCRYPTION_KEY') ? ENCRYPTION_KEY : null; // Replace with your actual key
}

function get_encryption_iv() {
    return defined('ENCRYPTION_IV') ? ENCRYPTION_IV : null; // Replace with your actual IV
}

// Custom Encrypted Login logic.
add_action('init', 'custom_encrypted_login');
function custom_encrypted_login() {
	if (!isset($_GET['direct-login']) || $_GET['direct-login'] != 'true') {
        return;
    }

    $key = get_encryption_key();
    $iv = get_encryption_iv();

    if (!$key || !$iv) {
        // Proper error handling if encryption key or IV is not set.
        error_log('Encryption key or IV is not set.');
        return;
    }

    $encryptedUsername = isset($_GET['username']) ? sanitize_text_field($_GET['username']) : '';
    $encryptedPassword = isset($_GET['password']) ? sanitize_text_field($_GET['password']) : '';

    $username = decrypt_data($encryptedUsername, $key, $iv);
    $password = decrypt_data($encryptedPassword, $key, $iv);

    if (empty($username) || empty($password)) {
        wp_redirect(home_url('/login-error')); // Redirect to a custom error page.
        exit;
    }

    $user = wp_authenticate($username, $password);

    if (!is_wp_error($user)) {
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);

        wp_redirect(home_url());
        exit;
    } else {
        wp_redirect(home_url('/login-error')); // Redirect to a custom error page.
        exit;
    }
}

/*
/////////////  Multiple Cart Session   ///////////////////////
*/

// Generate a unique cart identifier for each login session
function generate_cart_identifier() {
    $user_id = get_current_user_id();
    $session_token = wp_generate_password(12, false); // Generate a random token
    return 'cart_' . $user_id . '_' . $session_token;
}

// Store cart data in the session using the custom cart identifier
function store_cart_in_session($cart_data) {
    $cart_identifier = generate_cart_identifier();
    WC()->session->set($cart_identifier, $cart_data);
}

// Retrieve cart data from the session using the custom cart identifier
function get_cart_from_session() {
    $cart_identifier = generate_cart_identifier();
    return WC()->session->get($cart_identifier);
}


/*
/////////////  Punchout XML Processing   ///////////////////////
*/

// Register the custom rest route
add_action('rest_api_init', function () {
    register_rest_route('orbetec/v1', '/punchout_login', array(
        'methods' => 'POST',
        'callback' => 'handle_xml_request',
    ));
});

// Handle Login Request
function handle_xml_request(WP_REST_Request $request) {
    $returnCode = 'U'; // Default to 'Unexpected'
    $response_message = 'An unexpected error occurred.';
    $loginURL = '';

    try {
        $xml_data = $request->get_body();
        $xml = simplexml_load_string($xml_data);

        if (!$xml) {
            throw new Exception('Invalid XML format.');
        }

        $username = (string)$xml->header->login->username;
        $password = (string)$xml->header->login->password;

        if (empty($username) || empty($password)) {
            $returnCode = 'A';
            $response_message = 'Username or password missing.';
        } else {
            $user = wp_authenticate($username, $password);

            if (!is_wp_error($user)) {
                wp_set_current_user($user->ID);
                wp_set_auth_cookie($user->ID);

                $returnCode = 'S';

				 // Generate a unique session key and store it in a transient
				 $session_key = wp_generate_password(20, false);
				 $transient_name = 'session_key_' . $user->ID . '_' . time();
				 set_transient($transient_name, $session_key, DAY_IN_SECONDS); // Expires in 1 day

				 update_user_meta($user->ID, 'session_transient_name', $transient_name);
				 
				// Construct the login URL with the WordPress site's URL, session key, and additional parameters
				$loginURL = add_query_arg(array(
					'sessionKey' => $session_key,
					'action' => 'shopping',
					'language' => 'US',
					'searchKeywords' => urlencode('exampleKeyword') // Ensure proper URL encoding
				), home_url());

                $response_message = ''; // No message needed for success
            } else {
                $returnCode = 'A';
                $response_message = 'Authentication Failure';
            }
        }
    } catch (Exception $e) {
        $response_message = $e->getMessage();
    }

    // Prepare response data
    $response_data = [
        'returnCode' => $returnCode,
        'message' => $response_message,
        'loginURL' => $loginURL,
    ];

    // Generate and return the XML response
    $response_xml = generate_xml_response($response_data);
    return new WP_REST_Response($response_xml, 200, ['Content-Type' => 'application/xml']);
}


// Function to generate XML response from an array of response data
function generate_xml_response($response_data) {
    $dom = new DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = true;

    $response = $dom->createElement('response');
    $dom->appendChild($response);

    $header = $dom->createElement('header');
    $header->setAttribute('version', '1.0');
    $response->appendChild($header);

    $return = $dom->createElement('return');
    $return->setAttribute('returnCode', $response_data['returnCode']);
    $header->appendChild($return);

    // Handling success differently
    if ($response_data['returnCode'] === 'S') {
        if (!empty($response_data['loginURL'])) {
            $body = $dom->createElement('body');
            $response->appendChild($body);

            $loginURL = $dom->createElement('loginURL');
            $cdata = $dom->createCDATASection($response_data['loginURL']);
            $loginURL->appendChild($cdata);
            $body->appendChild($loginURL);
        }
    } else {
        // Include returnMessage for non-success codes
        if (!empty($response_data['message'])) {
            $returnMessage = $dom->createElement('returnMessage');
            $cdata = $dom->createCDATASection($response_data['message']);
            $returnMessage->appendChild($cdata);
            $return->appendChild($returnMessage);
        }

        // Ensure an empty loginURL is added to the body for non-success responses
        $body = $dom->createElement('body');
        $response->appendChild($body);
        $loginURL = $dom->createElement('loginURL');
        $body->appendChild($loginURL);
    }

    return $dom->saveXML();
}




//  Log In user using Login URL
add_action('init', 'custom_login_user_with_url_session_key');

function custom_login_user_with_url_session_key() {
    // Check if the session_key exists in the URL
    if (isset($_GET['session_key'])) {
        $session_key = $_GET['session_key'];

        // Validate the session key and log the user in
        if (custom_login_user_with_session_key($session_key)) {
            // Redirect to the homepage after successful login
            wp_redirect(home_url());
            exit;
        } else {
            $login_url = wp_login_url();
			$redirect_url = add_query_arg('login', 'failed', $login_url);
			wp_redirect($redirect_url);
			exit;
        }
    }
}

function custom_login_user_with_session_key($session_key) {
    // Assume validate_session_key function is defined and works as previously described
    $user_id = validate_session_key($session_key);

    if ($user_id) {
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);
        return true; // Login successful
    }

    return false; // Login failed
}

function validate_session_key($provided_session_key) {
    $users = get_users(array(
        'meta_key' => 'session_transient_name',
        'fields' => 'ids', // Only get user IDs to optimize the query.
    ));

    foreach ($users as $user_id) {
        $transient_name = get_user_meta($user_id, 'session_transient_name', true);
        $session_key = get_transient($transient_name);

        if ($session_key === $provided_session_key) {
            return $user_id;
        }
    }

    return false; // Return false if no matching session key is found.
}

function get_user_by_session_key($session_key) {
    // Query for users with the 'session_key' meta key matching the provided session key
    $users = get_users(array(
        'meta_key'     => 'session_key',
        'meta_value'   => $session_key,
        'number'       => 1,
        'count_total'  => false,
        'fields'       => 'ids', // Retrieve only the user IDs to improve performance
    ));

    // Check if we found a user
    if (!empty($users)) {
        return $users[0]; // Return the first user ID found
    }

    return null; // Return null if no matching user was found
}


add_filter('login_message', 'custom_login_failed_message');

function custom_login_failed_message($message) {
    if (isset($_GET['login']) && $_GET['login'] == 'failed') {
        $message .= '<div class="error"><p>Invalid session key. Please try again.</p></div>';
    }
    return $message;
}
