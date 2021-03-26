package org.keycloak.validate;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.validate.builtin.BuiltinValidators;
import org.keycloak.validate.builtin.LengthValidator;
import org.keycloak.validate.builtin.NotEmptyValidator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ValidatorTest {

    KeycloakSession session = null;

    @Test
    public void simpleValidation() {

        Validator validator = BuiltinValidators.notEmpty();

        {
            ValidationResult result = validator.validate("a").toResult();
            Assert.assertTrue(result.isValid());
        }

        {
            ValidationResult result = validator.validate("").toResult();
            Assert.assertFalse(result.isValid());
        }
    }

    @Test
    public void simpleValidationWithContext() {

        ValidationContext context = new ValidationContext(session);

        Validator validator = BuiltinValidators.length();

        validator.validate("a", "username", context);

        ValidationResult result = context.toResult();

        Assert.assertTrue(result.isValid());
    }

    @Test
    public void simpleValidationFluent() {

        ValidationContext context = new ValidationContext(session);

        ValidationResult result = BuiltinValidators.length().validate("a", "username", context).toResult();

        Assert.assertTrue(result.isValid());
    }

    @Test
    public void simpleValidationLookup() {

        ValidationContext context = new ValidationContext(session);

        Validator validator = ValidatorLookup.validator(session, LengthValidator.ID);

        validator.validate("a", "username", context);

        ValidationResult result = context.toResult();

        Assert.assertTrue(result.isValid());
    }

    @Test
    public void simpleValidationError() {

        ValidationContext context = new ValidationContext(session);

        String input = "a";
        String inputHint = "username";

        Validator validator = LengthValidator.INSTANCE;

        validator.validate(input, inputHint, context, Collections.singletonMap("min", "2"));

        ValidationResult result = context.toResult();

        Assert.assertFalse(result.isValid());
        Assert.assertEquals(1, result.getErrors().size());

        ValidationError[] errors = result.getErrors().toArray(new ValidationError[0]);
        ValidationError error = errors[0];

        Assert.assertNotNull(error);
        Assert.assertEquals(LengthValidator.ID, error.getValidatorId());
        Assert.assertEquals(inputHint, error.getInputHint());
        Assert.assertEquals(LengthValidator.ERROR_INVALID_LENGTH, error.getMessage());
        Assert.assertEquals(input, error.getMessageParameters()[0]);
    }


    @Test
    public void multipleValidations() {

        ValidationContext context = new ValidationContext(session);

        String input = "aaa";
        String inputHint = "username";

        BuiltinValidators.length().validate(input, inputHint, context);
        BuiltinValidators.notEmpty().validate(input, inputHint, context);

        ValidationResult result = context.toResult();

        Assert.assertTrue(result.isValid());
    }

    @Test
    public void multipleValidationsError() {

        ValidationContext context = new ValidationContext(session);

        String input = "";
        String inputHint = "username";

        BuiltinValidators.length().validate(input, inputHint, context, Collections.singletonMap("min", 1));
        BuiltinValidators.notEmpty().validate(input, inputHint, context);

//        Map<String, Map<String, Object>> configs = new HashMap<>();
//        configs.put(LengthValidator.ID, Collections.singletonMap("min", 1));

//        Stream.of(LengthValidator.INSTANCE, NotEmptyValidator.INSTANCE).forEach(v -> {
//            v.validate(input, inputHint, context, configs.get(v.getId()));
//        });

        ValidationResult result = context.toResult();

        Assert.assertFalse(result.isValid());
        Assert.assertEquals(2, result.getErrors().size());

        ValidationError[] errors = result.getErrors().toArray(new ValidationError[0]);

        ValidationError error1 = errors[1];

        Assert.assertNotNull(error1);
        Assert.assertEquals(NotEmptyValidator.ID, error1.getValidatorId());
        Assert.assertEquals(inputHint, error1.getInputHint());
        Assert.assertEquals(NotEmptyValidator.ERROR_EMPTY, error1.getMessage());
        Assert.assertEquals(input, error1.getMessageParameters()[0]);
    }

    @Test
    public void validateValidatorConfig() {

        Validator validator = LengthValidator.INSTANCE;

        Assert.assertTrue(validator.validateConfig(null).isValid());
        Assert.assertTrue(validator.validateConfig(Collections.singletonMap("min", 1)).isValid());
        Assert.assertTrue(validator.validateConfig(Collections.singletonMap("max", 100)).isValid());

        {
            Map<String, Object> config = new HashMap<>();
            config.put("min", 1);
            config.put("max", 10);
            Assert.assertTrue(validator.validateConfig(config).isValid());
        }

        Assert.assertFalse(validator.validateConfig(Collections.singletonMap("min", null)).isValid());
        Assert.assertFalse(validator.validateConfig(Collections.singletonMap("min", "123")).isValid());

        {
            Map<String, Object> config = new HashMap<>();
            config.put("min", "1");
            config.put("max", new ArrayList<>());
            ValidationResult result = validator.validateConfig(config);
            Assert.assertFalse(result.isValid());

            Assert.assertEquals(2, result.getErrors().size());

            ValidationError[] errors = result.getErrors().toArray(new ValidationError[0]);

            ValidationError error1 = errors[1];

            Assert.assertNotNull(error1);
            Assert.assertEquals(LengthValidator.ID, error1.getValidatorId());
            Assert.assertEquals("max", error1.getInputHint());
            Assert.assertEquals(LengthValidator.ERROR_INVALID_VALUE, error1.getMessage());
            Assert.assertEquals(new ArrayList<>(), error1.getMessageParameters()[0]);
        }
    }
}