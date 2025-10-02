package utils

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/paycrest/aggregator/types"
)

const (
	HTTP_RETRY_ATTEMPTS = 3
	HTTP_RETRY_INTERVAL = 5
)

// APIResponse is a helper function to return an API response
func APIResponse(ctx *gin.Context, httpCode int, status string, message string, data interface{}) {
	ctx.JSON(httpCode, types.Response{
		Status:  status,
		Message: message,
		Data:    data,
	})
}

// GetErrorMsg returns a list of meaningful error messages from binding tags.
// Reference: https://blog.logrocket.com/gin-binding-in-go-a-tutorial-with-examples/
func GetErrorMsg(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "lte":
		return "Should be less than " + fe.Param()
	case "gte":
		return "Should be greater than " + fe.Param()
	case "email":
		return "Must be a valid email address"
	case "min":
		return "Should be at least " + fe.Param() + " characters"
	case "max":
		return "Should be at most " + fe.Param() + " characters"
	case "oneof":
		options := strings.Split(fe.Param(), ",")
		return "Must be one of " + strings.Join(options, ", ")
	}
	return "Unknown error"
}

// GetErrorData returns a list of error data
func GetErrorData(err error) []types.ErrorData {
	var errorData []types.ErrorData
	for _, fe := range err.(validator.ValidationErrors) {
		errorData = append(errorData, types.ErrorData{
			Field:   fe.Field(),
			Message: GetErrorMsg(fe),
		})
	}
	return errorData
}

// Paginate parses the pagination query params and returns the offset(page) and limit(pageSize)
func Paginate(ctx *gin.Context) (page int, offset int, limit int) {
	// Parse pagination query params
	page, err := strconv.Atoi(ctx.Query("page"))
	pageSize, err2 := strconv.Atoi(ctx.Query("pageSize"))

	// Set defaults if not provided
	if err != nil || page < 1 {
		page = 1
	}
	if err2 != nil || pageSize < 1 {
		pageSize = 10
	}

	// Calculate offsets
	offset = (page - 1) * pageSize

	return page, offset, pageSize
}

// IsURL checks if a string is a valid URL
func IsURL(s string) bool {
	_, err := url.ParseRequestURI(s)
	return err == nil
}
