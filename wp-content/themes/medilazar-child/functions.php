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


function custom_login_endpoint() {
	// echo 'dfdf';
    add_rewrite_endpoint('custom-login', EP_ROOT);
	flush_rewrite_rules();
}
add_action('init', 'custom_login_endpoint');

function custom_login_handler() {
	// echo 'qqqqqqqqqqqqqqqqqqqqq';
	// print_r($_GET);
    if (isset($_GET['username']) && isset($_GET['password'])) {
        $username = sanitize_text_field($_GET['username']);
        $password = sanitize_text_field($_GET['password']);
		// echo $username;
		// echo $password;
		
	
        // Validate the username and password
        if (wp_authenticate($username, $password)) {
			// echo '<pre>';
			// print_r(wp_authenticate($username, $password));

			// $user_obj = wp_authenticate($username, $password);


			$creds = array();
    $creds['user_login'] = $username;
    $creds['user_password'] = $password;
    $creds['remember'] = true;
    $user = wp_signon( $creds, false );
    if ( is_wp_error($user) ) {
       echo $user->get_error_message();
       die();
    } else {
        //  wp_set_auth_cookie( $user, 0, 0);
		// wp_set_auth_cookie( $user->ID, 0, 0);
		wp_generate_auth_cookie($user->ID, 1209600);
		//  print_r($user);
		 echo wp_generate_auth_cookie($user->ID, 1209600);
		//  die;
    }


            // Authentication successful, generate a token
            // $token = wp_generate_auth_cookie($user_obj->ID, 1209600); // 2 weeks

			// print_r($user->ID);
			// echo get_current_user_id();
			// echo $token;
			// die;

            // Redirect to the home page with the token
            // wp_redirect(home_url('?token=' . $token));
			wp_redirect(home_url());
            exit;
        }
    }
}
add_action('template_redirect', 'custom_login_handler');


add_action('init', 'custom_direct_login');
function custom_direct_login() {
    if (isset($_GET['direct-login']) && $_GET['direct-login'] == 'true') {
        $username = $_GET['username'];
        $password = $_GET['password'];

        $user = wp_authenticate($username, $password);

        if (!is_wp_error($user)) {
            wp_clear_auth_cookie();
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);

            // Redirect after successful login to the homepage or dashboard as needed
            wp_redirect(home_url());
            exit;
        } else {
            // Handle login error (optional)
            wp_redirect(home_url() . '/login-error'); // Redirect to a custom error page (you need to create this)
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

// Custom login logic.
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


