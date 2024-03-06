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


// Multiple Cart Session

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
